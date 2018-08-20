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
        private static readonly string GroupId = ConfigurationManager.AppSettings["groupId"];
        private static readonly string ReportId = ConfigurationManager.AppSettings["reportId"];
        private static readonly string RedirectUrl = ConfigurationManager.AppSettings["redirectUrl"];
        private static readonly string BaseUri = ConfigurationManager.AppSettings["powerBIDataset"];
        public class PBIReports
        {
            public PBIReport[] value { get; set; }
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


        public async Task<ActionResult> Index()
        {

            if (Request.Cookies.AllKeys.Contains("token"))
            {
                // If we have a token go ahead and use it
                ViewData["token"] = Request.Cookies["token"];
            }
            else if (Request.QueryString.AllKeys.Contains("code"))
            {
                // If we have a code, we need to exchange that for a token
                string strToken = await GetAccessToken(Request.QueryString["code"], ClientId, ClientSecret, RedirectUrl);
                Response.Cookies.Add(new HttpCookie("token", strToken));
                ViewData["token"] = strToken;
            }
            else
            {
                // No token or code so have the user login and get a code
                GetAuthorizationCode();
            }

            return View();
        }

        public void GetAuthorizationCode()
        {
            var paramList = new NameValueCollection();
            paramList.Add("response_type", "code");
            paramList.Add("client_id", ClientId);
            paramList.Add("resource", ResourceUrl);
            paramList.Add("redirect_uri", RedirectUrl);

            // string strUrl = QueryHelpers.AddQueryString(AuthorityUrl, paramList);
            var queryString = HttpUtility.ParseQueryString(string.Empty);
            queryString.Add(@paramList);
            string strUrl = String.Format(AuthorityUrl + "?{0}", queryString);
            Response.Redirect(strUrl);
        }

        public async Task<string> GetAccessToken(string authorizationCode, string clientID, string clientSecret, string redirectUri)
        {
            TokenCache TC = new TokenCache();

            AuthenticationContext AC = new AuthenticationContext(AuthorityUrl, TC);
            ClientCredential cc = new ClientCredential(clientID, clientSecret);

            AuthenticationResult result = await AC.AcquireTokenByAuthorizationCodeAsync(authorizationCode, new Uri(redirectUri), cc);
            return result.AccessToken;
        }



        //public ActionResult Index()
        //{
        //    return View();
        //}

        public async Task<ActionResult> Run(string reportid, string groupid, string username, string roles)
        {
            if (Request.Cookies.AllKeys.Contains("token"))
            {
                // If we have a token go ahead and use it
                ViewData["token"] = Request.Cookies["token"];
            }
            else if (Request.QueryString.AllKeys.Contains("code"))
            {
                // If we have a code, we need to exchange that for a token
                string strToken = await GetAccessToken(Request.QueryString["code"], ClientId, ClientSecret, RedirectUrl);

                Response.Cookies.Add(new HttpCookie("token", strToken));
                ViewData["token"] = strToken;

            }
            else
            {
                // No token or code so have the user login and get a code
                GetAuthorizationCode();
            }
            var report = GetReport(reportid, groupid);
            var result = new ReportModel();
            if (report == null)
                result.ErrorMessage = "Report not found";
            else
            {
                result.Token = (string)ViewData["token"];
                //result.EmbedUrl = report.webUrl;
                result.EmbedUrl = report.embedUrl;
                result.Id = report.id;
                result.GroupId = groupid;
            }
            return View(result);
        }


        public async Task<ActionResult> OldRun(string reportid, string groupid, string username, string roles)
        {
            if (Request.Cookies.AllKeys.Contains("token"))
            {
                // If we have a token go ahead and use it
                ViewData["token"] = Request.Cookies["token"];
            }
            else if (Request.QueryString.AllKeys.Contains("code"))
            {
                // If we have a code, we need to exchange that for a token
                string strToken = await GetAccessToken(Request.QueryString["code"], ClientId, ClientSecret, RedirectUrl);

                Response.Cookies.Add(new HttpCookie("token", strToken));
                //Mihin mennään? 
                //Response.Redirect("/Home/Run");
            }
            else
            {
                // No token or code so have the user login and get a code
                GetAuthorizationCode();
            }

            var result = new EmbedConfig();
            try
            {
                result = new EmbedConfig { Username = username, Roles = roles };
                var error = GetWebConfigErrors();
                if (error != null)
                {
                    result.ErrorMessage = error;
                    return View(result);
                }


                // Create a user password cradentials.
                var credential = new UserPasswordCredential(Username, Password);

                // Authenticate using created credentials
                var authenticationContext = new AuthenticationContext(AuthorityUrl);
                var authenticationResult = await authenticationContext.AcquireTokenAsync(ResourceUrl, ClientId, credential);
                /////

                if (authenticationResult == null)
                {
                    result.ErrorMessage = "Authentication Failed.";
                    return View(result);
                }

                var tokenCredentials = new TokenCredentials(authenticationResult.AccessToken, "Bearer");

                // Create a Power BI Client object. It will be used to call Power BI APIs.
                using (var client = new PowerBIClient(new Uri(ApiUrl), tokenCredentials))
                {
                    // Get a list of reports.
                    var groupId = (groupid ?? GroupId);
                    var reports = await client.Reports.GetReportsInGroupAsync(groupId);

                    Report report;
                    var reportId = (reportid ?? ReportId);
                    if (string.IsNullOrEmpty(reportId))
                    {
                        //// Get the first report in the group.
                        //report = reports.Value.FirstOrDefault();
                        report = null;
                    }
                    else
                    {
                        report = reports.Value.FirstOrDefault(r => r.Id == reportId);
                    }

                    if (report == null)
                    {
                        result.ErrorMessage = "RaporttiId puuttuu";
                        return View(result);
                    }

                    var datasets = await client.Datasets.GetDatasetByIdInGroupAsync(groupId, report.DatasetId);
                    result.IsEffectiveIdentityRequired = datasets.IsEffectiveIdentityRequired;
                    result.IsEffectiveIdentityRolesRequired = datasets.IsEffectiveIdentityRolesRequired;
                    GenerateTokenRequest generateTokenRequestParameters;
                    // This is how you create embed token with effective identities
                    if (!string.IsNullOrEmpty(username))
                    {
                        var rls = new EffectiveIdentity(username, new List<string> { report.DatasetId });
                        if (!string.IsNullOrWhiteSpace(roles))
                        {
                            var rolesList = new List<string>();
                            rolesList.AddRange(roles.Split(','));
                            rls.Roles = rolesList;
                        }
                        // Generate Embed Token with effective identities.
                        generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view", identities: new List<EffectiveIdentity> { rls });
                    }
                    else
                    {
                        // Generate Embed Token for reports without effective identities.
                        generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view");
                    }

                    var tokenResponse = await client.Reports.GenerateTokenInGroupAsync(groupId, report.Id, generateTokenRequestParameters);

                    if (tokenResponse == null)
                    {
                        result.ErrorMessage = "Failed to generate embed token.";
                        return View(result);
                    }

                    // Generate Embed Configuration.
                    result.EmbedToken = tokenResponse;
                    result.EmbedUrl = report.EmbedUrl;
                    result.Id = report.Id;

                    return View(result);
                }
            }
            catch (HttpOperationException exc)
            {
                result.ErrorMessage = string.Format("Status: {0} ({1})\r\nResponse: {2}\r\nRequestId: {3}", exc.Response.StatusCode, (int)exc.Response.StatusCode, exc.Response.Content, exc.Response.Headers["RequestId"].FirstOrDefault());
            }
            catch (Exception exc)
            {
                result.ErrorMessage = exc.ToString();
            }

            return View(result);
        }

        public async Task<ActionResult> EmbedReport(string username, string roles)
        {
            var result = new EmbedConfig();
            try
            {
                result = new EmbedConfig { Username = username, Roles = roles };
                var error = GetWebConfigErrors();
                if (error != null)
                {
                    result.ErrorMessage = error;
                    return View(result);
                }

                // Create a user password cradentials.
                var credential = new UserPasswordCredential(Username, Password);

                // Authenticate using created credentials
                var authenticationContext = new AuthenticationContext(AuthorityUrl);
                var authenticationResult = await authenticationContext.AcquireTokenAsync(ResourceUrl, ClientId, credential);

                if (authenticationResult == null)
                {
                    result.ErrorMessage = "Authentication Failed.";
                    return View(result);
                }

                var tokenCredentials = new TokenCredentials(authenticationResult.AccessToken, "Bearer");

                // Create a Power BI Client object. It will be used to call Power BI APIs.
                using (var client = new PowerBIClient(new Uri(ApiUrl), tokenCredentials))
                {
                    // Get a list of reports.
                    var reports = await client.Reports.GetReportsInGroupAsync(GroupId);

                    Report report;
                    if (string.IsNullOrEmpty(ReportId))
                    {
                        // Get the first report in the group.
                        report = reports.Value.FirstOrDefault();
                    }
                    else
                    {
                        report = reports.Value.FirstOrDefault(r => r.Id == ReportId);
                    }

                    if (report == null)
                    {
                        result.ErrorMessage = "Group has no reports.";
                        return View(result);
                    }

                    var datasets = await client.Datasets.GetDatasetByIdInGroupAsync(GroupId, report.DatasetId);
                    result.IsEffectiveIdentityRequired = datasets.IsEffectiveIdentityRequired;
                    result.IsEffectiveIdentityRolesRequired = datasets.IsEffectiveIdentityRolesRequired;
                    GenerateTokenRequest generateTokenRequestParameters;
                    // This is how you create embed token with effective identities
                    if (!string.IsNullOrEmpty(username))
                    {
                        var rls = new EffectiveIdentity(username, new List<string> { report.DatasetId });
                        if (!string.IsNullOrWhiteSpace(roles))
                        {
                            var rolesList = new List<string>();
                            rolesList.AddRange(roles.Split(','));
                            rls.Roles = rolesList;
                        }
                        // Generate Embed Token with effective identities.
                        generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view", identities: new List<EffectiveIdentity> { rls });
                    }
                    else
                    {
                        // Generate Embed Token for reports without effective identities.
                        generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view");
                    }

                    var tokenResponse = await client.Reports.GenerateTokenInGroupAsync(GroupId, report.Id, generateTokenRequestParameters);

                    if (tokenResponse == null)
                    {
                        result.ErrorMessage = "Failed to generate embed token.";
                        return View(result);
                    }

                    // Generate Embed Configuration.
                    result.EmbedToken = tokenResponse;
                    result.EmbedUrl = report.EmbedUrl;
                    result.Id = report.Id;

                    return View(result);
                }
            }
            catch (HttpOperationException exc)
            {
                result.ErrorMessage = string.Format("Status: {0} ({1})\r\nResponse: {2}\r\nRequestId: {3}", exc.Response.StatusCode, (int)exc.Response.StatusCode, exc.Response.Content, exc.Response.Headers["RequestId"].FirstOrDefault());
            }
            catch (Exception exc)
            {
                result.ErrorMessage = exc.ToString();
            }

            return View(result);
        }

        public async Task<ActionResult> EmbedDashboard()
        {
            var error = GetWebConfigErrors();
            if (error != null)
            {
                return View(new EmbedConfig()
                {
                    ErrorMessage = error
                });
            }

            // Create a user password cradentials.
            var credential = new UserPasswordCredential(Username, Password);

            // Authenticate using created credentials
            var authenticationContext = new AuthenticationContext(AuthorityUrl);
            var authenticationResult = await authenticationContext.AcquireTokenAsync(ResourceUrl, ClientId, credential);

            if (authenticationResult == null)
            {
                return View(new EmbedConfig()
                {
                    ErrorMessage = "Authentication Failed."
                });
            }

            var tokenCredentials = new TokenCredentials(authenticationResult.AccessToken, "Bearer");

            // Create a Power BI Client object. It will be used to call Power BI APIs.
            using (var client = new PowerBIClient(new Uri(ApiUrl), tokenCredentials))
            {
                // Get a list of dashboards.
                var dashboards = await client.Dashboards.GetDashboardsInGroupAsync(GroupId);

                // Get the first report in the group.
                var dashboard = dashboards.Value.FirstOrDefault();

                if (dashboard == null)
                {
                    return View(new EmbedConfig()
                    {
                        ErrorMessage = "Group has no dashboards."
                    });
                }

                // Generate Embed Token.
                var generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view");
                var tokenResponse = await client.Dashboards.GenerateTokenInGroupAsync(GroupId, dashboard.Id, generateTokenRequestParameters);

                if (tokenResponse == null)
                {
                    return View(new EmbedConfig()
                    {
                        ErrorMessage = "Failed to generate embed token."
                    });
                }

                // Generate Embed Configuration.
                var embedConfig = new EmbedConfig()
                {
                    EmbedToken = tokenResponse,
                    EmbedUrl = dashboard.EmbedUrl,
                    Id = dashboard.Id
                };

                return View(embedConfig);
            }
        }

        public async Task<ActionResult> EmbedTile()
        {
            var error = GetWebConfigErrors();
            if (error != null)
            {
                return View(new TileEmbedConfig()
                {
                    ErrorMessage = error
                });
            }

            // Create a user password cradentials.
            var credential = new UserPasswordCredential(Username, Password);

            // Authenticate using created credentials
            var authenticationContext = new AuthenticationContext(AuthorityUrl);
            var authenticationResult = await authenticationContext.AcquireTokenAsync(ResourceUrl, ClientId, credential);

            if (authenticationResult == null)
            {
                return View(new TileEmbedConfig()
                {
                    ErrorMessage = "Authentication Failed."
                });
            }

            var tokenCredentials = new TokenCredentials(authenticationResult.AccessToken, "Bearer");

            // Create a Power BI Client object. It will be used to call Power BI APIs.
            using (var client = new PowerBIClient(new Uri(ApiUrl), tokenCredentials))
            {
                // Get a list of dashboards.
                var dashboards = await client.Dashboards.GetDashboardsInGroupAsync(GroupId);

                // Get the first report in the group.
                var dashboard = dashboards.Value.FirstOrDefault();

                if (dashboard == null)
                {
                    return View(new TileEmbedConfig()
                    {
                        ErrorMessage = "Group has no dashboards."
                    });
                }

                var tiles = await client.Dashboards.GetTilesInGroupAsync(GroupId, dashboard.Id);

                // Get the first tile in the group.
                var tile = tiles.Value.FirstOrDefault();

                // Generate Embed Token for a tile.
                var generateTokenRequestParameters = new GenerateTokenRequest(accessLevel: "view");
                var tokenResponse = await client.Tiles.GenerateTokenInGroupAsync(GroupId, dashboard.Id, tile.Id, generateTokenRequestParameters);

                if (tokenResponse == null)
                {
                    return View(new TileEmbedConfig()
                    {
                        ErrorMessage = "Failed to generate embed token."
                    });
                }

                // Generate Embed Configuration.
                var embedConfig = new TileEmbedConfig()
                {
                    EmbedToken = tokenResponse,
                    EmbedUrl = tile.EmbedUrl,
                    Id = tile.Id,
                    dashboardId = dashboard.Id
                };

                return View(embedConfig);
            }
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
        protected PBIReport GetReport(string reportid, string groupid)
        {
            //Configure Reports request
            System.Net.WebRequest request = null;
            if (groupid != null)
            {
                request = System.Net.WebRequest.Create(
                    String.Format("{0}/groups/{1}/Reports",
                    BaseUri, groupid)) as System.Net.HttpWebRequest;
            }
            else
            {
                request = System.Net.WebRequest.Create(
                    String.Format("{0}/Reports",
                    BaseUri)) as System.Net.HttpWebRequest;
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
                            return Reports.value[0];
                        else
                            foreach (var report in Reports.value)
                            {
                                if (report.id == reportid)
                                {
                                    return report;
                                }
                            }
                    }
                    return null;
                }
            }
        }
    }

}
