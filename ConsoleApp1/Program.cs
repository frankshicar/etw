using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;
namespace ConsoleApp1
{
    class Program
    {
        static FileSystemWatcher watcher;
        static TraceEventSession traceEventSession;
        static HashSet<string> monitoredProcesses;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as administrator");
                return;
            }

            // 讀取 XML 配置文件
            //var config = XDocument.Load("etwrole.xml");
            var config = XDocument.Load(@"C:\Users\User\Desktop\etw test\etw\ConsoleApp1\bin\Debug\etwrole.xml");
            var watcherConfig = config.Element("Configuration").Element("FileSystemWatcherConfig");
            var processMonitorConfig = config.Element("Configuration").Element("ProcessMonitorConfig");

            monitoredProcesses = new HashSet<string>();

            if (processMonitorConfig != null)
            {
                foreach (var name in processMonitorConfig.Elements("Name"))
                {
                    monitoredProcesses.Add(name.Value);
                    Console.WriteLine("Added to monitoring: " + name.Value);
                }
            }



            // 初始化 ETW
            InitializeETW();

            // 使用配置文件初始化 FileSystemWatcher
            InitializeFileSystemWatcher(
                watcherConfig.Element("Path").Value,
                watcherConfig.Element("Filter").Value,
                watcherConfig.Element("NotifyFilter").Value
            );

            Console.WriteLine("Monitoring started. Press 'Enter' to quit.");
            Console.ReadLine();

            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
            traceEventSession.Dispose();

        }


        private static void InitializeETW()
        {
            traceEventSession = new TraceEventSession("MyETWSession");
            traceEventSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad);
            traceEventSession.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational);
            traceEventSession.Source.Kernel.ProcessStart += data =>
            {
                if (monitoredProcesses.Any(process => Regex.IsMatch(data.CommandLine, Regex.Escape(process), RegexOptions.IgnoreCase)))
                {
                    OnProcessStarted(data);
                }
            };
            traceEventSession.Source.Kernel.ProcessStop += data =>
            {
                if (monitoredProcesses.Any(process => Regex.IsMatch(data.CommandLine, Regex.Escape(process), RegexOptions.IgnoreCase)))
                {
                    OnProcessStopped(data);
                }
            };
            //traceEventSession.Source.Kernel.ImageLoad += data =>
            //{
            //    if (monitoredProcesses.Contains(data.ProcessName.ToLower()))
            //    {
            //        OnImageLoaded(data);
            //    }
            //};

            // 處理網絡事件
            traceEventSession.Source.Dynamic.All += data =>
            {
                if (data.ProviderName == "Microsoft-Windows-TCPIP")
                {
                    if (data.EventName == "TcpConnectTcbComplete")
                    {
                        Console.WriteLine($"[TcpConnectTcbCompleteEvent] at {data.TimeStamp}");
                        foreach (var payloadName in data.PayloadNames)
                        {
                            var payloadValue = data.PayloadByName(payloadName);
                            if (payloadName == "LocalAddress" || payloadName == "RemoteAddress")
                            {
                                payloadValue = BytesToIPAddressString(payloadValue as byte[]);
                            }
                            Console.WriteLine($"  {payloadName}: {payloadValue}");
                        }
                    }
                }
            };

            var etwThread = new Thread(() => traceEventSession.Source.Process());
            etwThread.Start();
        }

        private static string BytesToIPAddressString(byte[] bytes)
        {
            if (bytes == null || bytes.Length != 4 && bytes.Length != 16)
            {
                return "Invalid IP Address";
            }
            return new IPAddress(bytes).ToString();
        }

        static void InitializeFileSystemWatcher(string path, string filter, string notifyFilter)
        {
            watcher = new FileSystemWatcher
            {
                Path = path,
                Filter = filter,
                NotifyFilter = ParseNotifyFilters(notifyFilter)
            };

            watcher.Changed += OnChanged;
            watcher.Created += OnCreated;
            watcher.Deleted += OnDeleted;
            watcher.Renamed += OnRenamed;
            watcher.Error += OnError;

            watcher.EnableRaisingEvents = true;
        }

        static NotifyFilters ParseNotifyFilters(string notifyFilter)
        {
            NotifyFilters filters = NotifyFilters.LastAccess;
            string[] tokens = notifyFilter.Split(',');
            foreach (var token in tokens)
            {
                if (Enum.TryParse(token.Trim(), out NotifyFilters result))
                {
                    filters |= result;
                }
            }
            return filters;
        }


        private static void OnProcessStarted(ProcessTraceData data)
        {
            Console.WriteLine($"[ProcessStart] {data.ProcessName} (PID: {data.ProcessID}) started. Provider: {data.ProviderName}, Event: ProcessStart, Command Line: {data.CommandLine}\n");
        }

        private static void OnProcessStopped(ProcessTraceData data)
        {

            Console.WriteLine($"[ProcessStop] {data.ProcessName} (PID: {data.ProcessID}) stopped. Provider: {data.ProviderName}, Event: ProcessStop, Command Line: {data.CommandLine}\n");

        }


        //private static void OnImageLoaded(ImageLoadTraceData data)
        //{
        //    Console.WriteLine($"[ImageLoad] {data.FileName} loaded by {data.ProcessName} with PID {data.ProcessID}Provider: {data.ProviderName}, Event: ImageLoad");
        //}
        private static void OnChanged(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileChanged] {e.FullPath}");
        }

        private static void OnCreated(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileCreated] {e.FullPath}");
        }

        private static void OnDeleted(object source, FileSystemEventArgs e)
        {
            Console.WriteLine($"[FileDeleted] {e.FullPath}");
        }

        private static void OnRenamed(object source, RenamedEventArgs e)
        {
            Console.WriteLine($"[FileRenamed] from {e.OldFullPath} to {e.FullPath}");
        }
        private static void OnError(object source, ErrorEventArgs e)
        {
            Console.WriteLine($"[WatcherError] {e.GetException().Message}");
        }
    }
}
