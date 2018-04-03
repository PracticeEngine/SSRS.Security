using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;

namespace SSRS.OpenIDConnect.Security
{
    public class OidcLogon : System.Web.UI.Page
    {
        private void Page_Load(object sender, System.EventArgs e)
        {
            if (Request.HttpMethod.Equals("post", StringComparison.OrdinalIgnoreCase))
            {
                FormsAuthentication.RedirectFromLoginPage(
                  "AzureAD\\RyanPosener", false);
            }
        }
    }
}
