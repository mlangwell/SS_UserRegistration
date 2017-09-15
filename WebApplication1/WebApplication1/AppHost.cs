using System;
using System.Diagnostics;
using Funq;
using ServiceStack;
using ServiceStack.Api.Swagger;
using ServiceStack.Auth;
using ServiceStack.Caching;
using ServiceStack.Data;
using ServiceStack.OrmLite;
using ServiceStack.Text;
using System.IO;
using System.Text;
using Svr.ServiceInterface;

namespace Svr.WebHost
{
    public class AppHost : AppHostBase
    {
        /// <summary>
        /// Base constructor requires a Name and Assembly where web service implementation is located
        /// </summary>
        public AppHost()
            : base("Svr.WebHost") { }

        /// <summary>
        /// Application specific configuration
        /// This method should initialize any IoC resources utilized by your web service classes.
        /// </summary>
        public override void Configure(Container container)
        {
            //Set JSON web services to return idiomatic JSON camelCase properties
            ServiceStack.Text.JsConfig.EmitCamelCaseNames = true;

            // overrides to default ServiceStack configuration
            SetConfig(new HostConfig
            {
                EnableFeatures = Feature.All,
                DefaultContentType = "application/json",
                DebugMode = true,       // show stack traces
                WriteErrorsToResponse = true,
                AdminAuthSecret = "A0verrid3" // TODO: drop this in Production
            });

            Plugins.Add(new CorsFeature(
                allowedOrigins: "*",
                allowedHeaders: "Content-Type, Authorization",
                allowCredentials: true
                ));

            Plugins.Add(new RequestLogsFeature
            {
            });

            Plugins.Add(new SwaggerFeature
            {
                DisableAutoDtoInBodyParam = false,
            });

            // return dates like this: 2012-08-21T11:02:32.0449348-04:00
            ServiceStack.Text.JsConfig.DateHandler = ServiceStack.Text.DateHandler.ISO8601;

            // make sure default connection profile exists
            var custData = System.Configuration.ConfigurationManager.ConnectionStrings["dbCustData"].ConnectionString;
            var data = System.Configuration.ConfigurationManager.ConnectionStrings["dbData"].ConnectionString;

            // TODO: setup correct db... We use SQL Server
            var cp = "Data Source=localhost;Initial Catalog=AuthDb;User ID=sa;Password=123;Connect Timeout=3600";


            //Register IOC dependencies
            container.Register<DbContext>(ctx => new DbContext(cp)).ReusedWithin(ReuseScope.Request);

            // handle exceptions in services
            this.ServiceExceptionHandlers.Add((httpReq, requestDto, ex) =>
            {
                return DtoUtils.CreateErrorResponse(requestDto, ex);
            });

            // handle exceptions not in services
            this.UncaughtExceptionHandlers.Add((httpReq, httpResp, operationName, ex) =>
            {
                // TODO: Figure out what changed between ServiceStack -Version 4.0.33 -> 4.0.62 as this throws an error as HttpResponse has already been submitted
                //httpResp.Write("Error: {0}: {1}".Fmt(ex.GetType().Name, ex.Message));
                httpResp.EndRequest(skipHeaders: true);

                // FUTURE: perhaps save errors to db
            });

            this.GlobalRequestFilters.Add((req, res, dto) =>
            {
                Stopwatch sw = new Stopwatch();
                sw.Start();
                req.Items.Add("StopWatch", sw);
            });

            this.GlobalResponseFilters.Add((req, res, dto) =>
            {
                if (req.Items.ContainsKey("StopWatch"))
                {
                    var sw = req.Items["StopWatch"] as Stopwatch;
                    sw.Stop();
                };
            });

            /* TODO: determine which db to house auth info in
             * for now, dump into CustData* (NA as default)
            */
            ConfigureAuth(container, cp);
        }

        private void ConfigureAuth(Container container, string authDbcs)
        {
            //Store UserAuth in SQL Server
            var dbFactory = new OrmLiteConnectionFactory(authDbcs, SqlServerDialect.Provider);

            container.Register<IDbConnectionFactory>(dbFactory);
            container.Register<IAuthRepository>(c => new OrmLiteAuthRepository(dbFactory) { UseDistinctRoleTables = true });

            //Create UserAuth RDBMS Tables
            var authRepo = container.Resolve<IAuthRepository>();
            authRepo.InitSchema();

            // TODO: don't seed generic users in production
            // seed with test user
            if (authRepo.GetUserAuthByUserName("admin") == null)
            {
                authRepo.CreateUserAuth(new Auth.AuthUser
                {
                    UserName = "admin",
                    Email = "admin@user.com",
                    Roles = { ServiceStack.Configuration.RoleNames.Admin },
                    ShopId = 99999,
                }, "admin123");

                var adminUser = authRepo.GetUserAuthByUserName("admin");
                authRepo.AssignRoles(adminUser, new System.Collections.Generic.List<String>() { "Admin" });

                authRepo.CreateUserAuth(new Auth.AuthUser
                {
                    UserName = "TestUser",
                    Email = "test@user.com",
                    Roles = { "Estimator", "Mixer", "Painter" },
                    ShopId = 99999,
                }, "password123");

                var testUser = authRepo.GetUserAuthByUserName("TestUser");
                authRepo.AssignRoles(testUser, new System.Collections.Generic.List<String>() { "User" });
            }

            //Also store User Sessions in SQL Server
            container.RegisterAs<OrmLiteCacheClient, ICacheClient>();
            var cacheClient = container.Resolve<ICacheClient>();
            cacheClient.InitSchema();
            // purge all cache session records effectively invalidating all previous tokens when this service starts up
            cacheClient.FlushAll();

            //Add Support for 
            Plugins.Add(new AuthFeature(() => new AuthUserSession(),
                new IAuthProvider[] {
                    new JwtAuthProvider(AppSettings) {
                        HashAlgorithm = "HS256",
                        AuthKey = GetSecurityKeyBytes(AppSettings.Get<string>("JwtSecurityKey", String.Empty)), // allow override with app.config
                        //ExpireTokensInDays = 1, // FUTURE: make this a more reasonable expiration in production
                        ExpireTokensInDays = 7, // 1 Week
                        Issuer = "SvrAppHost",
                        Audience = "http://*:8080", // FUTURE: Should this reflect api listening port?
                        SetBearerTokenOnAuthenticateResponse = true,
                        
                        /*
                         * This should get handled when we move to production
                         * HUGE TODO: get a valid SSL cert 
                         * and have this auth piece handled over HTTPS 
                         * also having ServiceStack bind/listen on HTTP *AND* HTTPS
                        */
                        RequireSecureConnection = false,
                    },
                    //new ApiKeyAuthProvider(AppSettings),        //Sign-in with API Key
                    new CredentialsAuthProvider(),              //Sign-in with UserName/Password credentials
                    //new BasicAuthProvider(),                    //Sign-in with HTTP Basic Auth
                    //new DigestAuthProvider(AppSettings),        //Sign-in with HTTP Digest Auth
                    //new TwitterAuthProvider(AppSettings),       //Sign-in with Twitter
                    //new FacebookAuthProvider(AppSettings),      //Sign-in with Facebook
                    //new YahooOpenIdOAuthProvider(AppSettings),  //Sign-in with Yahoo OpenId
                    //new OpenIdOAuthProvider(AppSettings),       //Sign-in with Custom OpenId
                    //new GoogleOAuth2Provider(AppSettings),      //Sign-in with Google OAuth2 Provider
                    //new LinkedInOAuth2Provider(AppSettings),    //Sign-in with LinkedIn OAuth2 Provider
                    //new GithubAuthProvider(AppSettings),        //Sign-in with GitHub OAuth Provider
                    //new YandexAuthProvider(AppSettings),        //Sign-in with Yandex OAuth Provider        
                    //new VkAuthProvider(AppSettings),            //Sign-in with VK.com OAuth Provider 
            }));

            //Provide service for new users to register so they can login with supplied credentials.
            Plugins.Add(new RegistrationFeature());
        }

        private const string SECURITY_PASSPHRASE = "ThisIsAnImportantStringAndIHaveNoIdeaIfThisIsVerySecureOrNot!";
        public static byte[] GetSecurityKeyBytes(string passphrase = null)
        {
            if (String.IsNullOrWhiteSpace(passphrase))
                return Encoding.Default.GetBytes(SECURITY_PASSPHRASE);
            else
                return Encoding.Default.GetBytes(passphrase);
        }
    }
}