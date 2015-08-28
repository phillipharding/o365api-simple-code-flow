//Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license. See full license at the bottom of this file.
//
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;
using System.Reflection;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.Security.Claims;
using SimpleWebAppCodeFlow.App_Classes;
using SimpleWebAppCodeFlow.Models;
using System.Diagnostics;
using Microsoft.SharePoint.Client;
using System.Xml.Linq;

namespace SimpleWebAppCodeFlow.Controllers
{
   // From: Jason Johnston@https://github.com/jasonjoh/office365-azure-guides/blob/master/code/parse-token.cs
   static class Base64UrlEncoder
   {
      static char Base64PadCharacter = '=';
      static string DoubleBase64PadCharacter = String.Format(CultureInfo.InvariantCulture, "{0}{0}", Base64PadCharacter);
      static char Base64Character62 = '+';
      static char Base64Character63 = '/';
      static char Base64UrlCharacter62 = '-';
      static char Base64UrlCharacter63 = '_';

      public static byte[] DecodeBytes(string arg)
      {
         string s = arg;
         s = s.Replace(Base64UrlCharacter62, Base64Character62); // 62nd char of encoding
         s = s.Replace(Base64UrlCharacter63, Base64Character63); // 63rd char of encoding
         switch (s.Length % 4) // Pad 
         {
            case 0:
               break; // No pad chars in this case
            case 2:
               s += DoubleBase64PadCharacter; break; // Two pad chars
            case 3:
               s += Base64PadCharacter; break; // One pad char
            default:
               throw new ArgumentException("Illegal base64url string!", arg);
         }
         return Convert.FromBase64String(s); // Standard base64 decoder
      }

      public static string Decode(string arg)
      {
         return Encoding.UTF8.GetString(DecodeBytes(arg));
      }
   }

   public class HomeController : Controller
   {
      private static AppConfig appConfig = new AppConfig();

      [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
      public class MultipleButtonAttribute : ActionNameSelectorAttribute
      {
         public string Name { get; set; }
         public string Argument { get; set; }

         public override bool IsValidName(ControllerContext controllerContext, string actionName, MethodInfo methodInfo)
         {
            var isValidName = false;
            var keyValue = string.Format("{0}:{1}", Name, Argument);
            var value = controllerContext.Controller.ValueProvider.GetValue(keyValue);

            if (value != null)
            {
               controllerContext.Controller.ControllerContext.RouteData.Values[Name] = Argument;
               isValidName = true;
            }

            return isValidName;
         }
      }

      private static async Task<string> GetFormDigest(string siteURL, string accessToken)
      {
         HttpClient client = new HttpClient();
         var request = new HttpRequestMessage(HttpMethod.Post, siteURL + "/_api/contextinfo");
         request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));
         request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
         var response = await client.SendAsync(request);
         string responseString = await response.Content.ReadAsStringAsync();
         XNamespace d = "http://schemas.microsoft.com/ado/2007/08/dataservices";
         var root = XElement.Parse(responseString);
         var formDigestValue = root.Element(d + "FormDigestValue").Value;

         return formDigestValue;
      }

      //
      // GET: /Home/
      public async Task<ActionResult> Index()
      {
         // Force SSL
         if (!Request.IsSecureConnection)
         {
            string httplength = "http";
            string nonsecureurl = Request.Url.AbsoluteUri.Substring(httplength.Length);
            string secureurl = String.Format("https{0}", nonsecureurl);
            RedirectResult result = Redirect(secureurl);
            result.ExecuteResult(this.ControllerContext);
         }

         // This is where state of the app is maintained and data passed between view and controller
         AppState appState = new AppState();

         // Authorization back from AAD in a form post as requested in the authorize request
         if (!Request.Form.HasKeys())
         {
            return View(appState);
         }

         // Cool we have a form post

         // Did it return with an error?
         if (!String.IsNullOrEmpty(Request.Form["error"]))
         {
            appState.ErrorMessage = Request.Form["error"];
            return View(appState);
         }

         // Was it correlated with authorize request
         var authstate = Session[AppSessionVariables.AuthState] as String;
         Session[AppSessionVariables.AuthState] = null;
         if (String.IsNullOrEmpty(authstate))
         {
            appState.ErrorMessage = "Oops. Something went wrong with the authorization state (No auth state). Please retry.";
            return View(appState);
         }
         if (!Request.Form["state"].Equals(authstate))
         {
            appState.ErrorMessage = "Oops. Something went wrong with the authorization state (Invalid auth state). Please retry.";
            return View(appState);
         }

         // Authorized without error: Check to see if we have an ID token and code
         if (String.IsNullOrEmpty(Request.Form["id_token"]) || String.IsNullOrEmpty(Request.Form["code"]))
         {
            return View(appState);
         }

         try
         {
            // Get the TenantId out of the ID Token to address tenant specific token endpoint.
            // No validation of ID Token as the only info we need is the tenantID
            // If for any case your app wants to use the ID Token to authenticate 
            // it must be validated.
            JwtToken openIDToken = DecodeIDToken(Request.Form["id_token"]);
            appState.TenantId = openIDToken.tid;
            appState.TenantDomain = openIDToken.domain;
            appState.LoggedOnUser = openIDToken.upn;

            // Get an app-only access token for the AAD Graph Rest APIs
            var token = await GetAccessTokenByAuthorisationCode(Request.Form["code"], appState.TenantId);
            appState.AccessToken = token.access_token;
            appState.AccessTokenAquiredWithoutError = true;
            appState.AppIsAuthorized = true;

            SetSessionInProgress();

            /* Make a SharePoint REST (GET) call using the AAD access token */
            var siteUrl = "https://platinumdogsconsulting.sharepoint.com/sites/publishing";
            var requestUrl = siteUrl + "/_api/Web/Lists";
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("application/json;odata=verbose"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.access_token);
            var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
               var responseString = await response.Content.ReadAsStringAsync();
               Debug.WriteLine(string.Format("\n***REST (GET) API  Response:\n{0}\n", responseString));

               var spLists = JsonConvert.DeserializeObject<SpListJsonCollection>(responseString);
               appState.RestWebLists = spLists.d.results;
            }
            else
            {
               Debug.WriteLine(string.Format("***REST (GET) API RESPONSE ERROR: {0}, {1}", response.StatusCode, response.ReasonPhrase));
            }

            /* Make a SharePoint REST (POST) call using the AAD access token */
            var formDigest = await GetFormDigest(siteUrl, token.access_token);

            var announcementTitle = string.Format("Welcome from SimpleWebAppCodeFlow - {0}", DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss"));
            requestUrl = siteUrl + "/_api/Web/Lists/GetByTitle('Announcements')/Items";
            request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("application/json;odata=verbose"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.access_token);
            request.Headers.Add("X-RequestDigest", formDigest);

            var requestContent = new StringContent("{ '__metadata': { 'type': 'SP.Data.AnnouncementsListItem' }, 'Title': '" + announcementTitle + "'}");
            requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json;odata=verbose");
            request.Content = requestContent;
            response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
               var responseString = await response.Content.ReadAsStringAsync();
               Debug.WriteLine(string.Format("\n***REST (POST) API Response:\n{0}\n", responseString));
            }
            else
            {
               Debug.WriteLine(string.Format("***REST (POST) API RESPONSE ERROR: {0}, {1}", response.StatusCode, response.ReasonPhrase));
            }

            /* Make a SharePoint CSOM call using the AAD access token */
            var ctx = new ClientContext(siteUrl);
            ctx.ExecutingWebRequest += (sender, e) =>
                  {
                     e.WebRequestExecutor.RequestHeaders["Authorization"] = "Bearer " + token.access_token;
                  };

            var web = ctx.Web;
            ctx.Load(web, w => w.Title, w => w.Url);
            ctx.ExecuteQuery();
            appState.CsomWebTitle = web.Title;
            appState.CsomWebUrl = web.Url;
         }
         catch (Exception ex)
         {
            appState.ErrorMessage = ex.Message;
         }

         return View(appState);
      }

      private void SetSessionInProgress()
      {
         Session[AppSessionVariables.IsAuthorized] = true;
      }

      private bool IsSessionInProgress()
      {
         bool? inprogress = Session[AppSessionVariables.IsAuthorized] as bool?;
         if (null == inprogress)
            return false;

         return (bool)inprogress;
      }

      private ViewResult RedirectHome()
      {
         RedirectResult result = Redirect(appConfig.RedirectUri);
         result.ExecuteResult(this.ControllerContext);

         return View("Index", new AppState());
      }

      [HttpPost]
      [MultipleButton(Name = "action", Argument = "StartOver")]
      public ActionResult StartOver(AppState passedAppState)
      {
         if (!IsSessionInProgress())
         {
            return RedirectHome();
         }

         AppState appState = new AppState();

         Session.Clear();

         UriBuilder signOutRequest = new UriBuilder(appConfig.SignoutUri.Replace("common", passedAppState.TenantId));

         signOutRequest.Query = "post_logout_redirect_uri=" + HttpUtility.UrlEncode(appConfig.RedirectUri);

         RedirectResult result = Redirect(signOutRequest.Uri.ToString());
         result.ExecuteResult(this.ControllerContext);

         return View("Index", appState);
      }

      [HttpPost]
      [MultipleButton(Name = "action", Argument = "Authorize")]
      public ActionResult Authorize(AppState passedAppState)
      {
         passedAppState.AppIsAuthorized = false;

         // hit the common endpoint for authorization, 
         // after authorization we will use the tenant specific endpoint for getting app-only tokens
         UriBuilder authorizeRequest = new UriBuilder(appConfig.AuthorizationUri);

         // Maintain state for authorize request to prvenet cross forgery attacks
         var authstate = Guid.NewGuid().ToString();
         Session[AppSessionVariables.AuthState] = authstate;

         authorizeRequest.Query =
                 "state=" + authstate +
                 "&response_type=code+id_token" +
                 "&scope=openid" +
                 "&nonce=" + Guid.NewGuid().ToString() +
                 "&client_id=" + appConfig.ClientId +
                 "&redirect_uri=" + HttpUtility.UrlEncode(appConfig.RedirectUri) +
                 "&resource=" + HttpUtility.UrlEncode(appConfig.SharePointResourceUri) +
#if DEBUG1
                    "&login_hint=" + "some-user@some-tenant.onmicrosoft.com" +
#endif
//                    "&prompt=consent" +
                 "&response_mode=form_post";

         RedirectResult result = Redirect(authorizeRequest.Uri.ToString());
         result.ExecuteResult(this.ControllerContext);

         return View("Index", passedAppState);
      }

      private string Base64UrlDecodeJwtTokenPayload(string base64UrlEncodedJwtToken)
      {
         string payload = base64UrlEncodedJwtToken.Split('.')[1];
         return Base64UrlEncoder.Decode(payload);
      }

      public class JwtToken
      {
         public string tid { get; set; }
         public string upn { get; set; }
         public string domain { get { return (string.IsNullOrEmpty(upn)) ? "string.Empty" : upn.Split('@')[1]; } }
      }

      private JwtToken DecodeIDToken(string id_token)
      {
         string encodedOpenIdToken = id_token;

         string decodedToken = Base64UrlDecodeJwtTokenPayload(encodedOpenIdToken);

         JwtToken token = JsonConvert.DeserializeObject<JwtToken>(decodedToken);

         return token;
      }

      public class AADCodeFlowSuccessResponse
      {
         //{
         //  "token_type": "Bearer",
         //  "expires_in": "3600",
         //  "expires_on": "1423336547",
         //  "not_before": "1423332647",
         //  "resource": "https://outlook.office365.com/",
         //  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciO....ZVvynkUXjZPNg1oJWDKBymPL-U0WA"
         //  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciO....ZVvynkUXjZPNg1oJWDKBymPL-U0WA"
         //  "scope": "Mail.Read"
         //}
         public string token_type;
         public string expires_in;
         public string expires_on;
         public string not_before;
         public string resource;
         public string access_token;
         public string refresh_token;
         public string scope;
      };

      public class AADErrorResponse
      {
         //{
         //  "error": "invalid_client",
         //  "error_description": "AADSTS70002: Error ...",
         //  "error_codes": [
         //    70002,
         //    50012
         //  ],
         //  "timestamp": "2015-02-07 18:44:09Z",
         //  "trace_id": "dabcfa26-ea8d-46c5-81bc-ff57a0895629",
         //  "correlation_id": "8e270f2d-ba05-42fb-a7ab-e819d142c843",
         //  "submit_url": null,
         //  "context": null
         //}
         public string error;
         public string error_description;
         public string[] error_codes;
         public string timestamp;
         public string trace_id;
         public string correlation_id;
         public string submit_url;
         public string context;
      }

      private async Task<AADCodeFlowSuccessResponse> GetAccessTokenByAuthorisationCode(string code, string tenantId)
      {
         string tokenIssueEndpoint = appConfig.TokenIssueingUri.Replace("common", tenantId);

         /**
          * build the request payload
          */
         FormUrlEncodedContent tokenRequestForm;
         tokenRequestForm = new FormUrlEncodedContent(
             new[] {
                    new KeyValuePair<string,string>("grant_type","authorization_code"),
                    new KeyValuePair<string,string>("code",code),
                    new KeyValuePair<string,string>("client_id", appConfig.ClientId),
                    new KeyValuePair<string,string>("client_secret", appConfig.ClientSecret),
                    new KeyValuePair<string,string>("redirect_uri", appConfig.RedirectUri)
             }
         );

         /*
          * Do the web request
          */
         HttpClient client = new HttpClient();

         Task<string> requestString = tokenRequestForm.ReadAsStringAsync();
         StringContent requestContent = new StringContent(requestString.Result);
         requestContent.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
         requestContent.Headers.Add("client-request-id", System.Guid.NewGuid().ToString());
         requestContent.Headers.Add("return-client-request-id", "true");
         requestContent.Headers.Add("UserAgent", "MatthiasLeibmannsWebAppCodeFlow/0.1");

         HttpResponseMessage response = client.PostAsync(tokenIssueEndpoint, requestContent).Result;
         JObject jsonResponse = JObject.Parse(response.Content.ReadAsStringAsync().Result);
         JsonSerializer jsonSerializer = new JsonSerializer();

         if (response.IsSuccessStatusCode == true)
         {
            AADCodeFlowSuccessResponse s = (AADCodeFlowSuccessResponse)jsonSerializer.Deserialize(new JTokenReader(jsonResponse), typeof(AADCodeFlowSuccessResponse));
            return s;
         }

         AADErrorResponse e = (AADErrorResponse)jsonSerializer.Deserialize(new JTokenReader(jsonResponse), typeof(AADErrorResponse));
         throw new Exception(e.error_description);
      }
   }
}
// MIT License: 

// Permission is hereby granted, free of charge, to any person obtaining 
// a copy of this software and associated documentation files (the 
// ""Software""), to deal in the Software without restriction, including 
// without limitation the rights to use, copy, modify, merge, publish, 
// distribute, sublicense, and/or sell copies of the Software, and to 
// permit persons to whom the Software is furnished to do so, subject to 
// the following conditions: 

// The above copyright notice and this permission notice shall be 
// included in all copies or substantial portions of the Software. 

// THE SOFTWARE IS PROVIDED ""AS IS"", WITHOUT WARRANTY OF ANY KIND, 
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
