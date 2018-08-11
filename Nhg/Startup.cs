using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Nhg.Startup))]
namespace Nhg
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
        }
    }
}
