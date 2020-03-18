using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.PowerBI.Api.V2;
using Microsoft.PowerBI.Api.V2.Models;
using Microsoft.Rest;
using Nhg.Models;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Collections.Specialized;
using Newtonsoft.Json;

namespace Nhg.Controllers
{
    public class HomeController : Controller
    {
        private static readonly string Username = ConfigurationManager.AppSettings["pbiUsername"];
        private static readonly string Password = ConfigurationManager.AppSettings["pbiPassword"];
        private static readonly string AuthorityUrl = ConfigurationManager.AppSettings["authorityUrl"];
        private static readonly string ResourceUrl = ConfigurationManager.AppSettings["resourceUrl"];
        private static readonly string ClientId = ConfigurationManager.AppSettings["clientId"];
        private static readonly string ClientSecret = ConfigurationManager.AppSettings["clientSecret"];
        private static readonly string ApiUrl = ConfigurationManager.AppSettings["apiUrl"];
        private static readonly string RedirectUrl = ConfigurationManager.AppSettings["redirectUrl"];
        private static readonly string BaseUri = ConfigurationManager.AppSettings["powerBIDataset"];

        private string GroupId = ConfigurationManager.AppSettings["groupId"];
        private string ReportId = ConfigurationManager.AppSettings["reportId"];
        private string UserId = null;
        private string UserName = null;


        public class PBIReports
        {
            //public PBIReport[] value { get; set; }
            public ReportModel[] value { get; set; }
        }
        public class PBIReport
        {
            public string id { get; set; }
            public string name { get; set; }
            public string webUrl { get; set; }
            public string embedUrl { get; set; }
        }


        // Sends an OpenIDConnect Sign-In Request.  
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {

                HttpContext.GetOwinContext()
                    .Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/" },
                        OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }


        //  Signs the user out and clears the cache of access tokens.  
        public void SignOut()
        {

            HttpContext.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
        }



        public async Task<string> GetAccessToken(string authorizationCode, string clientID, string clientSecret, string redirectUri)
        {
            TokenCache TC = new TokenCache();

            AuthenticationContext AC = new AuthenticationContext(AuthorityUrl, TC);
            ClientCredential cc = new ClientCredential(clientID, clientSecret);

            AuthenticationResult result = await AC.AcquireTokenByAuthorizationCodeAsync(authorizationCode, new Uri(redirectUri), cc);
            this.UserId = result.UserInfo.UniqueId;
            this.UserName = result.UserInfo.DisplayableId;
            return result.AccessToken;
        }

        public async Task<ActionResult> Run(string reportid, string groupid, string username, string roles)
        {
            if (Request.Cookies["token"] != null)
            {
                // If we have a token go ahead and use it
                ViewData["token"] = Request.Cookies["token"].Value;
                string state = Request.QueryString["state"];
                if (state != null)
                {
                    this.ReportId = state.Split('/')[0];
                    this.GroupId = state.Split('/')[1];
                }
                else
                {
                    this.ReportId = reportid;
                    this.GroupId = groupid;
                }

            }
            else if (Request.QueryString.AllKeys.Contains("code"))
            {
                // If we have a code, we need to exchange that for a token
                string strToken = await GetAccessToken(Request.QueryString["code"], ClientId, ClientSecret, RedirectUrl);
                //string strToken = strResult.Split('/')[0];
                //string userId = strResult.Split('/')[1];

                HttpCookie tokenCookie = new HttpCookie("token");
                tokenCookie.Value = strToken;
                tokenCookie.Expires = DateTime.Now.AddSeconds(3600);
                Response.Cookies.Add(tokenCookie);

                ViewData["token"] = strToken;
                string state = Request.QueryString["state"];
                if (state != null)
                {
                    ReportId = state.Split('/')[0];
                    GroupId = state.Split('/')[1];
                }
                else
                {
                    this.ReportId = reportid;
                    this.GroupId = groupid;
                }
            }
            else
            {
                // No token or code so have the user login and get a code
                ReportId = reportid;
                GroupId = groupid;
                GetAuthorizationCode();
            }
            /// Check if user has rights to ythe report
            /// 
            var testid = this.UserId;
            var testname = this.UserName;
            var report = GetReport(ReportId, GroupId);
            var result = new ReportModel();
            if (report == null)
                result.ErrorMessage = "Report not found";
            else
            {
                if (report.ErrorMessage != null)
                {
                    result.ErrorMessage = report.ErrorMessage;
                }
                else
                {
                    result.Token = (string)ViewData["token"];
                    //result.EmbedUrl = report.webUrl;
                    result.EmbedUrl = report.EmbedUrl;
                    result.Id = report.Id;
                    result.GroupId = groupid;
                }
            }
            return View(result);
        }


        /// <summary>
        /// Check if web.config embed parameters have valid values.
        /// </summary>
        /// <returns>Null if web.config parameters are valid, otherwise returns specific error string.</returns>
        private string GetWebConfigErrors()
        {
            // Client Id must have a value.
            if (string.IsNullOrEmpty(ClientId))
            {
                return "ClientId is empty. please register your application as Native app in https://dev.powerbi.com/apps and fill client Id in web.config.";
            }

            // Client Id must be a Guid object.
            Guid result;
            if (!Guid.TryParse(ClientId, out result))
            {
                return "ClientId must be a Guid object. please register your application as Native app in https://dev.powerbi.com/apps and fill client Id in web.config.";
            }

            // Group Id must have a value.
            if (string.IsNullOrEmpty(GroupId))
            {
                return "GroupId is empty. Please select a group you own and fill its Id in web.config";
            }

            // Group Id must be a Guid object.
            if (!Guid.TryParse(GroupId, out result))
            {
                return "GroupId must be a Guid object. Please select a group you own and fill its Id in web.config";
            }

            // Username must have a value.
            if (string.IsNullOrEmpty(Username))
            {
                return "Username is empty. Please fill Power BI username in web.config";
            }

            // Password must have a value.
            if (string.IsNullOrEmpty(Password))
            {
                return "Password is empty. Please fill password of Power BI username in web.config";
            }
            return null;
        }

        public void GetAuthorizationCode()
        {
            var paramList = new NameValueCollection();
            paramList.Add("response_type", "code");
            paramList.Add("client_id", ClientId);
            paramList.Add("resource", ResourceUrl);
            paramList.Add("redirect_uri", RedirectUrl);
            paramList.Add("state", ReportId + "/" + GroupId);


            // string strUrl = QueryHelpers.AddQueryString(AuthorityUrl, paramList);
            var queryString = HttpUtility.ParseQueryString(string.Empty);
            queryString.Add(@paramList);
            string strUrl = String.Format(AuthorityUrl + "?{0}", queryString);
            Response.Redirect(strUrl);
        }

        protected ReportModel GetReport(string reportid, string groupid)
        {
            //Configure Reports request
            try
            {
                System.Net.WebRequest request = null;
                if (groupid != null)
                {
                    request = System.Net.WebRequest.Create(
                        String.Format("{0}/Groups/{1}/Reports",
                        BaseUri, groupid)) as System.Net.HttpWebRequest;
                }
                else
                {
                    return null;
                }

                request.Method = "GET";
                request.ContentLength = 0;
                request.Headers.Add("Authorization", String.Format("Bearer {0}", ViewData["token"]));

                //Get Reports response from request.GetResponse()
                using (var response = request.GetResponse() as System.Net.HttpWebResponse)
                {
                    //Get reader from response stream
                    using (var reader = new System.IO.StreamReader(response.GetResponseStream()))
                    {
                        //Deserialize JSON string
                        PBIReports Reports = JsonConvert.DeserializeObject<PBIReports>(reader.ReadToEnd());

                        //Sample assumes at least one Report.
                        //You could write an app that lists all Reports
                        if (Reports.value.Length > 0)
                        {
                            if (reportid == null)
                                return null;
                            else
                                foreach (var report in Reports.value)
                                {
                                    if (report.Id == reportid)
                                    {
                                        return report;
                                    }
                                }
                        }
                        return null;
                    }
                }
            }
            catch (HttpOperationException exc)
            {
                var report = new ReportModel();
                report.ErrorMessage = string.Format("Status: {0} ({1})\r\nResponse: {2}\r\nRequestId: {3}", exc.Response.StatusCode, (int)exc.Response.StatusCode, exc.Response.Content, exc.Response.Headers["RequestId"].FirstOrDefault());
                return report;
            }
            catch (Exception exc)
            {
                var report = new ReportModel();
                report.ErrorMessage = exc.ToString();
                return report;
            }

        }
    }

}
