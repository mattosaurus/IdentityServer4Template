using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Serilog;

namespace IdentityService
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            #region X509
            X509Certificate2Collection certCollection = null;
            X509Store store = null;
            X509Certificate2 SigningCertificate = null;
            string certThumb = Configuration["CertificateValidation:Thumbprint"];
            store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            Log.Debug("STORENAME: " + store.Name);
            Log.Debug("STORELOCATION: " + store.Location);
            store.Open(OpenFlags.ReadOnly);

            certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, certThumb, false);
            Log.Debug("CERTS FOUND: " + certCollection.Count.ToString());
            foreach (X509Certificate2 x509 in certCollection)
            {
                try
                {
                    Log.Debug("FOUND THUMBPRINT: " + x509.Thumbprint);
                    Log.Debug("SEARCHED THUMBPRINT: " + certThumb);
                    if (x509.Thumbprint.ToUpper() == certThumb.ToUpper())
                    {
                        SigningCertificate = x509;
                        break;
                    }
                }
                catch (CryptographicException ex)
                {
                    Log.Error(ex.Message);
                }
            }
            #endregion

            try
            {
                if (SigningCertificate != null)
                {
                    Log.Information("SIGNING CERTIFICATE AQUIRED WITH THUMBPRINT:  \"" + certThumb + "\"");
                    services.AddIdentityServer()
                    //.AddTemporarySigningCredential()  //Use this for test purposes only
                    .AddSigningCredential(SigningCertificate)         //Use this to add trusted certificate or rsa key
                    .AddConfigurationStore(options =>
                    {
                        options.ConfigureDbContext = builder => builder.UseSqlServer(Configuration["ConnectionStrings:IdentityServiceConnection"]);
                        options.DefaultSchema = "IdentityService";
                    }
                    )
                    .AddOperationalStore(options =>
                    {
                        options.ConfigureDbContext = builder => builder.UseSqlServer(Configuration["ConnectionStrings:IdentityServiceConnection"], sql => sql.MigrationsAssembly(migrationsAssembly));
                        options.DefaultSchema = "IdentityService";
                    }
                    );
                }
                else
                {
                    Log.Warning("UNABLE TO AQUIRE SIGNING CERTIFICATE WITH THUMBPRINT:  \"" + certThumb + "\" USING TEMPORARY SIGNING CREDENTIAL");
                    services.AddIdentityServer()
                    .AddDeveloperSigningCredential()  //Use this for test purposes only
                    //.AddSigningCredential(SigningCertificate)         //Use this to add trusted certificate or rsa key
                    .AddConfigurationStore(options =>
                    {
                        options.ConfigureDbContext = builder => builder.UseSqlServer(Configuration["ConnectionStrings:IdentityServiceConnection"]);
                        options.DefaultSchema = "IdentityService";
                    }
                    )
                    .AddOperationalStore(options =>
                    {
                        options.ConfigureDbContext = builder => builder.UseSqlServer(Configuration["ConnectionStrings:IdentityServiceConnection"], sql => sql.MigrationsAssembly(migrationsAssembly));
                        options.DefaultSchema = "IdentityService";
                    }
                    );
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex.Message);
            }

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseIdentityServer();
            app.UseHttpsRedirection();
            app.UseMvc();
        }
    }
}
