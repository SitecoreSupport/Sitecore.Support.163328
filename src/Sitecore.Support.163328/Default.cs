namespace Sitecore.Support.sitecore.login
{
    using System;
    using System.Text.RegularExpressions;
    using System.Web;
    using System.Web.UI;
    using Sitecore.Configuration;
    using Sitecore.Diagnostics;
    using Sitecore.Globalization;
    using Sitecore.Pipelines;
    using Sitecore.Pipelines.LoggedIn;
    using Sitecore.Pipelines.LoggingIn;
    using Sitecore.Pipelines.PasswordRecovery;
    using Sitecore.Security.Accounts;
    using Sitecore.Security.Authentication;
    using Sitecore.SecurityModel.Cryptography;
    using Sitecore.Text;
    using Sitecore.Web;
    using Sitecore.Web.Authentication;
    using Sitecore.SecurityModel.License;
    using System.Web.UI.HtmlControls;
    using System.Web.UI.WebControls;

    /// <summary>
    /// </summary>
    public partial class Default : Page
    {
        #region Fields

        private string fullUserName = string.Empty;
        private string startUrl = string.Empty;

        #endregion

        /// <summary>
        /// LoginForm control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlForm LoginForm;

        /// <summary>
        /// FailureHolder control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder FailureHolder;

        /// <summary>
        /// FailureText control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected Literal FailureText;

        /// <summary>
        /// SuccessHolder control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder SuccessHolder;

        /// <summary>
        /// SuccessText control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected Literal SuccessText;

        /// <summary>
        /// loginLbl control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected Label loginLbl;

        /// <summary>
        /// UserName control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected TextBox UserName;

        /// <summary>
        /// UserNameRequired control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected RequiredFieldValidator UserNameRequired;

        /// <summary>
        /// passLabel control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected Label passLabel;

        /// <summary>
        /// Password control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected TextBox Password;

        /// <summary>
        /// RequiredFieldValidator1 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected RequiredFieldValidator RequiredFieldValidator1;

        /// <summary>
        /// PlaceHolder3 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder PlaceHolder3;

        /// <summary>
        /// PlaceHolder2 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder PlaceHolder2;

        /// <summary>
        /// RememberMe control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected CheckBox RememberMe;

        /// <summary>
        /// PlaceHolder1 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder PlaceHolder1;

        /// <summary>
        /// PlaceHolder4 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected PlaceHolder PlaceHolder4;

        /// <summary>
        /// UserNameForgot control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected TextBox UserNameForgot;

        /// <summary>
        /// licenseOptions control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlGenericControl licenseOptions;

        /// <summary>
        /// licenseInfo control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlGenericControl licenseInfo;

        /// <summary>
        /// StartPage control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlIframe StartPage;

        /// <summary>
        /// loginLink control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlGenericControl loginLink;

        #region Protected methods

        /// <summary>
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        protected void ForgotPasswordClicked(object sender, EventArgs e)
        {
            var userName = this.UserNameForgot.Text;
            this.fullUserName = WebUtil.HandleFullUserName(userName);

            if (Security.Accounts.User.Exists(this.fullUserName))
            {
                var passwordRecoveryArgs = new PasswordRecoveryArgs(this.Context)
                {
                    Username = userName
                };

                Pipeline.Start("passwordRecovery", passwordRecoveryArgs);
            }

            this.RenderSuccess("Your password has been sent to you. If you do not receive an e-mail with your password, please check that you've typed your user name correctly or contact your administrator.");
        }

        /// <summary>
        /// Returns the path to the background image for use on the login page
        /// </summary>
        /// <returns>Image url</returns>
        protected string GetBackgroundImageUrl()
        {
            return Settings.Login.BackgroundImageUrl;
        }

        /// <summary>
        /// Gets the login page URL.
        /// </summary>
        /// <returns></returns>
        protected string GetLoginPageUrl()
        {
            var loginPageUrl = Client.Site.LoginPage;
            return !string.IsNullOrEmpty(loginPageUrl) ? loginPageUrl : "/sitecore/login";
        }

        /// <summary>
        /// </summary>
        protected virtual void LoggedIn()
        {
            var user = Security.Accounts.User.FromName(this.fullUserName, false);

            State.Client.UsesBrowserWindows = true;

            var args = new LoggedInArgs
            {
                Username = this.fullUserName,
                StartUrl = this.startUrl,
                Persist = this.ShouldPersist()
            };

            Pipeline.Start("loggedin", args);
            var language = StringUtil.GetString(user.Profile.ClientLanguage, Settings.ClientLanguage);

            var url = args.StartUrl;

            var startUrlString = new UrlString(url);
            if (string.IsNullOrEmpty(startUrlString["sc_lang"]))
            {
                startUrlString["sc_lang"] = language;
            }

            this.startUrl = startUrlString.ToString();
            using (new UserSwitcher(user))
            {
                Log.Audit(this, "Login");
            }
        }

        /// <summary>
        /// </summary>
        protected virtual bool LoggingIn()
        {
            if (string.IsNullOrWhiteSpace(this.UserName.Text))
                return false;
            this.fullUserName = WebUtil.HandleFullUserName(this.UserName.Text);
            this.startUrl = WebUtil.GetQueryString("returnUrl");
            this.FailureHolder.Visible = false;
            this.SuccessHolder.Visible = false;

            if (Settings.Login.RememberLastLoggedInUserName)
            {
                WriteCookie(WebUtil.GetLoginCookieName(), this.UserName.Text);
            }

            var args = new LoggingInArgs
            {
                Username = this.fullUserName,
                Password = this.Password.Text,
                StartUrl = this.startUrl
            };

            Pipeline.Start("loggingin", args);

            var isIe11 = UIUtil.IsIE() || UIUtil.IsIE11();
            if (isIe11 && !Regex.IsMatch(WebUtil.GetHostName(), Settings.HostNameValidationPattern, RegexOptions.ECMAScript))
            {
                this.RenderError(Translate.Text(Texts.LOGIN_DNS_ILLEGAL_CHARACTER_IS_NOT_SUPPORTED));
                return false;
            }
            if (!args.Success)
            {
                Log.Audit(string.Format("Login failed: {0}.", args.Username), this);
                if (!string.IsNullOrEmpty(args.Message))
                {
                    this.RenderError(Translate.Text(StringUtil.RemoveLineFeeds(args.Message)));
                }
                return false;
            }

            this.startUrl = args.StartUrl;

            return true;
        }

        /// <summary>
        /// </summary>
        protected virtual bool Login()
        {
            if (AuthenticationManager.Login(this.fullUserName, this.Password.Text, this.ShouldPersist()))
            {
                return true;
            }
            this.RenderError("Your login attempt was not successful. Please try again.");
            return false;
        }

        /// <summary>
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        protected void LoginClicked(object sender, EventArgs e)
        {
            if (!this.LoggingIn())
            {
                return;
            }
            if (!this.Login())
            {
                return;
            }
            this.LoggedIn();
            this.CheckDomainGuard();

            WebUtil.Redirect(this.startUrl);
        }

        /// <summary>
        /// </summary>
        /// <param name="e"></param>
        protected override void OnInit(EventArgs e)
        {
            if (Sitecore.Context.User.IsAuthenticated)
            {
                if (WebUtil.GetQueryString("inv") == "1")
                {
                    Boost.Invalidate();
                }

                if (!DomainAccessGuard.GetAccess())
                {
                    this.LogMaxEditorsExceeded();
                    this.Response.Redirect(WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage"));
                    return;
                }
            }

            this.DataBind();

            if (Settings.Login.DisableRememberMe || Settings.Login.DisableAutoComplete)
            {
                this.LoginForm.Attributes.Add("autocomplete", "off");
            }

            if (!this.IsPostBack && Settings.Login.RememberLastLoggedInUserName && !Settings.Login.DisableAutoComplete)
            {
                var userName = WebUtil.GetCookieValue(WebUtil.GetLoginCookieName());
                if (!string.IsNullOrEmpty(userName))
                {
                    MachineKeyEncryption.TryDecode(userName, out userName);
                    this.UserName.Text = userName;
                    this.UserNameForgot.Text = userName;
                }
            }

            try
            {
                this.Response.Headers.Add("SC-Login", "true");
            }
            catch (PlatformNotSupportedException ex)
            {
                Log.Error("Setting response headers is not supported.", ex, this);
            }

            this.RenderSdnInfoPage();

            this.RemoveLicenseInfo();

            base.OnInit(e);
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Logs that the maximum number of simultaneously active (logged-in) editors was exceeded. 
        /// </summary>
        private void LogMaxEditorsExceeded()
        {
            var LogMessageFormat = @"The maximum number of simultaneously active (logged-in) editors exceeded. The User {0} cannot be logged in to the system. The maximum of editors allowed by license is {1}.";
            Log.Warn(string.Format(LogMessageFormat, this.fullUserName, DomainAccessGuard.MaximumSessions), this);
        }

        private static void WriteCookie([NotNull] string name, [NotNull] string value)
        {
            Assert.ArgumentNotNull(name, "name");
            Assert.ArgumentNotNull(value, "value");

            if (name == WebUtil.GetLoginCookieName())
            {
                value = MachineKeyEncryption.Encode(value);
            }

            var cookie = new HttpCookie(name, value)
            {
                Expires = DateTime.UtcNow.AddMonths(3),
                Path = "/sitecore/login",
                HttpOnly = true
            };

            HttpContext.Current.Response.AppendCookie(cookie);
            var addedCookie = HttpContext.Current.Request.Cookies[name];

            if (addedCookie != null)
            {
                addedCookie.Value = value;
            }
        }

        private void CheckDomainGuard()
        {
            if (!DomainAccessGuard.GetAccess())
            {
                this.LogMaxEditorsExceeded();
                this.startUrl = WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage");
            }
        }

        /// <summary>
        /// Renders the start page.
        /// </summary>
        private void RenderSdnInfoPage()
        {
            var cleansedUrl = Settings.Login.SitecoreUrl;
            if (this.Request.IsSecureConnection)
            {
                cleansedUrl = cleansedUrl.Replace("http:", "https:");
            }

            var url = new UrlString(cleansedUrl)
            {
                ["id"] = License.LicenseID,
                ["host"] = WebUtil.GetHostName(),
                ["licensee"] = License.Licensee,
                ["iisname"] = WebUtil.GetIISName(),
                ["st"] = WebUtil.GetCookieValue("sitecore_starttab", string.Empty),
                ["sc_lang"] = Sitecore.Context.Language.Name,
                ["v"] = About.GetVersionNumber(true)
            };
            // change to this value for testing "7.1.130926";
            this.StartPage.Attributes["src"] = url.ToString();
            this.StartPage.Attributes["onload"] = "javascript:this.style.display='block'";
        }

        private void RenderError(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.FailureHolder.Visible = true;
            this.FailureText.Text = text;
        }

        private void RenderSuccess(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.SuccessHolder.Visible = true;
            this.SuccessText.Text = text;
        }

        private bool ShouldPersist()
        {
            return !Settings.Login.DisableRememberMe && this.RememberMe.Checked;
        }

        private void RemoveLicenseInfo()
        {
            if (Settings.Login.DisableLicenseInfo)
            {
                licenseOptions.Visible = false;
            }
        }

        #endregion
    }
}