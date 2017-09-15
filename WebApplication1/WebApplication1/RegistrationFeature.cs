using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ServiceStack;
using ServiceStack.Auth;
using ServiceStack.FluentValidation;

namespace Registration
{
    public class RegistrationFeature : IPlugin
    {
        public string AtRestPath { get; set; }

        public RegistrationFeature()
        {
            this.AtRestPath = "/register";
        }

        public void Register(IAppHost appHost)
        {
            appHost.RegisterService<RegisterService>(AtRestPath);
            appHost.RegisterAs<RegistrationValidator, IValidator<UserRegister>>();
        }
    }

    public class UserRegister : Register
    {
        // FUTURE: bring these in the client registration request object so user can be assigned to valid shop/mso and not just auto-generated
        //public int ShopId { get; set; }
        //public int MSOShopId { get; set; }
        public string PhoneNumber { get; set; }
        // TODO: FILL IN rest of fields in AuthUser table we want to populate per new users being added to table
    }
}
