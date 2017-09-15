using ServiceStack.Auth;

namespace Auth
{
    public class AuthUser : UserAuth
    {
        public int ShopId { get; set; }
    }
}
