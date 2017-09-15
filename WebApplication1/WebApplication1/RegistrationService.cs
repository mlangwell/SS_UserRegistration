using System;
using System.Collections.Generic;
using System.Globalization;
using ServiceStack.FluentValidation;
using ServiceStack.Validation;
using ServiceStack.Web;
using ServiceStack;
using ServiceStack.Auth;
using System.Data.SqlClient;

namespace Registration
{
    public class FullRegistrationValidator : RegistrationValidator
    {
        public FullRegistrationValidator() { RuleSet(ApplyTo.Post, () => RuleFor(x => x.DisplayName).NotEmpty()); }
    }

    public class RegistrationValidator : AbstractValidator<UserRegister>
    {
        public RegistrationValidator()
        {
            RuleSet(
                ApplyTo.Post,
                () =>
                {
                    RuleFor(x => x.Password).NotEmpty();
                    RuleFor(x => x.UserName).NotEmpty().When(x => x.Email.IsNullOrEmpty());
                    RuleFor(x => x.Email).NotEmpty().EmailAddress().When(x => x.UserName.IsNullOrEmpty());
                    RuleFor(x => x.UserName)
                        .Must(x =>
                        {
                            var authRepo = HostContext.AppHost.GetAuthRepository(base.Request);
                            using (authRepo as IDisposable)
                            {
                                return authRepo.GetUserAuthByUserName(x) == null;
                            }
                        })
                        .WithErrorCode("AlreadyExists")
                        .WithMessage(ErrorMessages.UsernameAlreadyExists)
                        .When(x => !x.UserName.IsNullOrEmpty());
                    RuleFor(x => x.Email)
                        .Must(x =>
                        {
                            var authRepo = HostContext.AppHost.GetAuthRepository(base.Request);
                            using (authRepo as IDisposable)
                            {
                                return x.IsNullOrEmpty() || authRepo.GetUserAuthByUserName(x) == null;
                            }
                        })
                        .WithErrorCode("AlreadyExists")
                        .WithMessage(ErrorMessages.EmailAlreadyExists)
                        .When(x => !x.Email.IsNullOrEmpty());
                });
            RuleSet(
                ApplyTo.Put,
                () =>
                {
                    RuleFor(x => x.UserName).NotEmpty();
                    RuleFor(x => x.Email).NotEmpty();
                });
        }
    }

    [Obsolete("Use normal RegistrationFeature and have your IAuthRepository implement ICustomUserAuth instead")]
    [DefaultRequest(typeof(UserRegister))]
    public class RegisterService<TUserAuth> : RegisterService
        where TUserAuth : class, IUserAuth
    { }

    [DefaultRequest(typeof(UserRegister))]
    [RequiredRole("Admin")]
    public class RegisterService : Service
    {
        public static ValidateFn ValidateFn { get; set; }

        public IValidator<UserRegister> RegistrationValidator { get; set; }

        public IAuthEvents AuthEvents { get; set; }

        /// <summary>
        /// Update an existing registraiton
        /// </summary>
        public object Put(UserRegister request)
        {
            return Post(request);
        }

        /// <summary>
        ///     Create new Registration
        /// </summary>
        public object Post(UserRegister request)
        {
            var validateResponse = ValidateFn?.Invoke(this, HttpMethods.Post, request);
            if (validateResponse != null)
                return validateResponse;

            RegisterResponse response = null;
            var session = this.GetSession(true);
            bool registerNewUser;
            IUserAuth user;

            var authRepo = HostContext.AppHost.GetAuthRepository(base.Request);
            var newUserAuth = ToUserAuth(authRepo, request);
            using (authRepo as IDisposable)
            {
                var existingUser = authRepo.GetUserAuth(session, null);
                registerNewUser = existingUser == null;

                if (HostContext.GlobalRequestFilters == null
                    || !HostContext.GlobalRequestFilters.Contains(ValidationFilters.RequestFilter)) //Already gets run
                {
                    RegistrationValidator?.ValidateAndThrow(request, registerNewUser ? ApplyTo.Post : ApplyTo.Put);
                }

                user = registerNewUser
                    ? SaveNewUser(authRepo, newUserAuth, request.Password)
                    : authRepo.UpdateUserAuth(existingUser, newUserAuth, request.Password);

                //: throw new HttpError(System.Net.HttpStatusCode.NotAcceptable, "USER_EXISTS", "User already exists. Please enter a new user name.");

                var newUser = authRepo.GetUserAuthByUserName(user.UserName);
                authRepo.AssignRoles(newUser, new System.Collections.Generic.List<String>() { "User" });
            }

            if (request.AutoLogin.GetValueOrDefault())
            {
                using (var authService = base.ResolveService<AuthenticateService>())
                {
                    var authResponse = authService.Post(
                        new Authenticate
                        {
                            provider = CredentialsAuthProvider.Name,
                            UserName = request.UserName ?? request.Email,
                            Password = request.Password,
                            Continue = request.Continue
                        });

                    if (authResponse is IHttpError)
                        throw (Exception)authResponse;

                    var typedResponse = authResponse as AuthenticateResponse;
                    if (typedResponse != null)
                    {
                        response = new RegisterResponse
                        {
                            SessionId = typedResponse.SessionId,
                            UserName = typedResponse.UserName,
                            ReferrerUrl = typedResponse.ReferrerUrl,
                            UserId = user.Id.ToString(CultureInfo.InvariantCulture),
                        };
                    }

                    //return typedResponse;
                }
            }

            if (registerNewUser)
            {
                session = this.GetSession();
                if (!request.AutoLogin.GetValueOrDefault())
                    session.PopulateSession(user, new List<IAuthTokens>());

                session.OnRegistered(Request, session, this);
                AuthEvents?.OnRegistered(this.Request, session, this);
            }

            if (response == null)
            {
                response = new RegisterResponse
                {
                    UserId = user.Id.ToString(CultureInfo.InvariantCulture),
                    ReferrerUrl = request.Continue
                };
            }

            var isHtml = Request.ResponseContentType.MatchesContentType(MimeTypes.Html);
            if (isHtml)
            {
                if (string.IsNullOrEmpty(request.Continue))
                    return response;

                return new HttpResult(response)
                {
                    Location = request.Continue
                };
            }

            return response;
        }

        private IUserAuth SaveNewUser(IAuthRepository authRepo, IUserAuth newUserAuth, string password)
        {
            // this should be for the CustData* db...
            using (var cn = new SqlConnection(this.Db.ConnectionString))
            {
                cn.Open();
                // we use custom auth tables
                var shopId = 1;
                (newUserAuth as Auth.AuthUser).ShopId = shopId;
            }

            return authRepo.CreateUserAuth(newUserAuth, password);
        }

        public IUserAuth ToUserAuth(IAuthRepository authRepo, UserRegister request)
        {
            var customUserAuth = authRepo as ICustomUserAuth;
            var to = customUserAuth != null
                ? customUserAuth.CreateUserAuth()
                : new Auth.AuthUser();

            to.PopulateInstance(request);
            to.PrimaryEmail = request.Email;
            return to;
        }

        /// <summary>
        /// Logic to update UserAuth from Registration info, not enabled on PUT because of security.
        /// </summary>
        public object UpdateUserAuth(UserRegister request)
        {
            if (HostContext.GlobalRequestFilters == null
                || !HostContext.GlobalRequestFilters.Contains(ValidationFilters.RequestFilter))
            {
                RegistrationValidator.ValidateAndThrow(request, ApplyTo.Put);
            }

            var response = ValidateFn?.Invoke(this, HttpMethods.Put, request);
            if (response != null)
                return response;

            var session = this.GetSession();

            var authRepo = HostContext.AppHost.GetAuthRepository(base.Request);
            using (authRepo as IDisposable)
            {
                var existingUser = authRepo.GetUserAuth(session, null);
                if (existingUser == null)
                    throw HttpError.NotFound(ErrorMessages.UserNotExists);

                var newUserAuth = ToUserAuth(authRepo, request);
                authRepo.UpdateUserAuth(existingUser, newUserAuth, request.Password);

                return new RegisterResponse
                {
                    UserId = existingUser.Id.ToString(CultureInfo.InvariantCulture),
                };
            }
        }
    }
}