using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as administrator");
                return;
            }

            // 初始化 FileSystemWatcher
            InitializeFileSystemWatcher();

            // 設置 ETW 來監控進程事件
            using (var kernalSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernalSession.Dispose(); };

                kernalSession.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Process);

                kernalSession.Source.Kernel.ImageLoad += dllLoaded;
                kernalSession.Source.Kernel.ProcessStart += processStarted;
                kernalSession.Source.Kernel.ProcessStop += processStopped;

                kernalSession.Source.Process();
            }
        }

        private static void InitializeFileSystemWatcher()
        {
            using (FileSystemWatcher watcher = new FileSystemWatcher())
            {
                watcher.Path = @"C:\Users"; // 指定要監測的目錄路徑
                watcher.Filter = "*.*"; // 監測的檔案類型
                watcher.NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;

                // 註冊事件處理器
                watcher.Changed += OnChanged;
                watcher.Created += OnCreated;
                watcher.Deleted += OnDeleted;
                watcher.Renamed += OnRenamed;
                watcher.Error += OnError;

                // 開始監測
                watcher.EnableRaisingEvents = true;

                Console.WriteLine("FileSystemWatcher is running. Press 'q' to quit.");
            }
        }

        // FileSystemWatcher 的事件處理方法
        private static void OnChanged(object source, FileSystemEventArgs e) => Console.WriteLine($"File changed: {e.FullPath}");
        private static void OnCreated(object source, FileSystemEventArgs e) => Console.WriteLine($"File created: {e.FullPath}");
        private static void OnDeleted(object source, FileSystemEventArgs e) => Console.WriteLine($"File deleted: {e.FullPath}");
        private static void OnRenamed(object source, RenamedEventArgs e) => Console.WriteLine($"File renamed from {e.OldFullPath} to {e.FullPath}");
        private static void OnError(object source, ErrorEventArgs e) => Console.WriteLine($"FileSystemWatcher error.");

        // ETW 的事件處理方法
        private static void dllLoaded(ImageLoadTraceData data) => Console.WriteLine("DLL loaded: {0}, by process: {1} with pid: {2}", data.FileName, data.ProcessName, data.ProcessID);
        private static void processStarted(ProcessTraceData data) => Console.WriteLine("Process started: {0}, PID: {1}", data.ProcessName, data.ProcessID);
        private static void processStopped(ProcessTraceData data) => Console.WriteLine("Process stopped: {0}, PID: {1}", data.ProcessName, data.ProcessID);
    }
}



