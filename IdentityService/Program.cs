﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;

namespace IdentityService
{
    public class Program
    {
        public static IConfiguration Configuration { get; } = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        public static int Main(string[] args)
        {
            //Serilog.Debugging.SelfLog.Enable(msg => Debug.WriteLine(msg));

            ColumnOptions columnOptions = new ColumnOptions();
            // Don't include the Properties XML column.
            columnOptions.Store.Remove(StandardColumn.Properties);
            // Do include the log event data as JSON.
            columnOptions.Store.Add(StandardColumn.LogEvent);

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.MSSqlServer(Configuration.GetConnectionString("IdentityServiceConnection"), Configuration["Serilog:TableName"], columnOptions: columnOptions, schemaName: "IdentityService")
                .WriteTo.Console()
                .WriteTo.ApplicationInsightsEvents(Configuration["ApplicationInsights:InstrumentationKey"])
                .CreateLogger();

            try
            {
                Log.Information("Starting host");

                BuildWebHost(args).Run();

                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseApplicationInsights()
                .UseStartup<Startup>()
                .UseSerilog()
                .Build();
    }
}
