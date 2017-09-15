using System;

namespace Svr.ServiceInterface
{
    public class DbContext
    {
        private string _dbcs = null;

        public DbContext(string dbcs)
        {
            _dbcs = dbcs;
		}
    }
}
