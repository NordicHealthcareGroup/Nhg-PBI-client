using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Configuration;
using Owin;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Collections.Specialized;
using System.Web;
using System;

[assembly: OwinStartupAttribute(typeof(Nhg.Startup))]
namespace Nhg
{
    public partial class Startup
    {
        // Calling the keys values from Web.config file  
        private static string clientId = ConfigurationManager.AppSettings["clientId"];
        private static string tenant = ConfigurationManager.AppSettings["adTenat"];
        private static string aadInstance = ConfigurationManager.AppSettings["loginUrl"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["redirectUrl"];

        // Concatenate aadInstance, tenant to form authority value       
        private string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        // ConfigureAuth method  
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                            new OpenIdConnectAuthenticationOptions
                            {
                                ClientId = clientId,
                                Authority = authority,
                                PostLogoutRedirectUri = postLogoutRedirectUri,
                                Notifications = new OpenIdConnectAuthenticationNotifications
                                {
                                    AuthenticationFailed = (context) =>
                                    {
                                        context.HandleResponse();
                                        context.OwinContext.Response.Redirect("/Home/Run");
                                        return Task.FromResult(0);
                                    }
                                }
                            });


        } // end - ConfigureAuth method  




        public void Configuration(IAppBuilder app)
        {
            //ConfigureAuth(app);
        }
    }
}
