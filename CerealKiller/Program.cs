using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Threading;
using System.Threading.Tasks;
using Mono.Cecil;
using Mono.Cecil.Cil;



namespace CerealKiller
{
    internal class Program
    {
        private static bool _DECOMPLIE = false;
        static async Task Main(string[] args)
        {

            Option<string> pathOption = new Option<string>(
                new string[] { "--path", "-p" },
                "The path to a specific .NET assembly to analyze");
            Option<bool> scanOption = new Option<bool>(
                new string[] { "--scan", "-s" },
                "Scan the entire host for .NET assemblies and analyze each one");
            Option<string[]> methodOption = new Option<string[]>(
                new string[] { "--methods", "-m" },
                "The method to search for (e.g., System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize)")
            {
                Arity = ArgumentArity.OneOrMore
            };

            Option<bool> decompileOption = new Option<bool>(
                new string[] { "--decompile", "-d" },
                "Decompile any identified methods. WARNING - Creates a lot of output");

            RootCommand rootCommand = new(description: "Deserialization hunter for .NET assemblies")
            {
                pathOption,
                scanOption,
                methodOption,
                decompileOption
            };

            rootCommand.SetHandler(async (path, scan, methods, decompile) =>
                {
                    if (methods == null || methods.Length == 0)
                    {
                        Console.WriteLine("You must specify one or more methods to search for using --methods or -m");
                        return;
                    }

                    if (decompile)
                    {
                        _DECOMPLIE = true;
                    }

                    if (scan)
                    {
                        await ScanHostForAssemblies(methods);
                    }
                    else if (!string.IsNullOrEmpty(path))
                    {
                        FindMethodCalls(path, methods);
                    }
                    else
                    {
                        Console.WriteLine("You must specify either --path or --scan");
                    }
                },
                pathOption,
                scanOption,
                methodOption,
                decompileOption);
            await rootCommand.InvokeAsync(args);

        }



        static async Task ScanHostForAssemblies(string[] methodsToSearch)
        {
            string[] extensions = new[] { ".dll", ".exe" };
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => d.RootDirectory.FullName);

            var fileQueue = new ConcurrentQueue<string>();
            var dirQueue = new ConcurrentQueue<string>(drives);
            var tasks = new List<Task>();

            var processedDirectories = 0;
            var processedFiles = 0;

            var timer = new Timer(_ =>
            {
                Console.WriteLine($"Processed directories: {processedDirectories}, Queued files: {fileQueue.Count}");
            }, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));

            for (int i = 0; i < Environment.ProcessorCount; i++)
            {
                tasks.Add(Task.Run(() => ProcessDirectories(dirQueue, extensions, fileQueue, ref processedDirectories)));
            }

            await Task.WhenAll(tasks);
            timer.Dispose();

            var processingTasks = new List<Task>();
            while (fileQueue.TryDequeue(out var file))
            {
                Interlocked.Increment(ref processedFiles);
                processingTasks.Add(Task.Run(() =>
                {
                    try
                    {
                        if (IsDotNetAssembly(file))
                        {
                            FindMethodCalls(file, methodsToSearch);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error processing file {file}: {ex.Message}");
                    }
                }));
            }

            await Task.WhenAll(processingTasks);
            Console.WriteLine($"Processing complete. Processed files: {processedFiles}");
        }

        static void ProcessDirectories(ConcurrentQueue<string> dirQueue, string[] extensions, ConcurrentQueue<string> fileQueue, ref int processedDirectories)
        {
            while (dirQueue.TryDequeue(out var currentDir))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(currentDir))
                    {
                        if (extensions.Contains(Path.GetExtension(file)))
                        {
                            fileQueue.Enqueue(file);
                        }
                    }

                    foreach (var dir in Directory.GetDirectories(currentDir))
                    {
                        dirQueue.Enqueue(dir);
                    }

                    Interlocked.Increment(ref processedDirectories);
                }
                catch (UnauthorizedAccessException ex)
                {
                    //Console.WriteLine($"Access denied to directory: {currentDir}. Error: {ex.Message}");
                }
                catch (PathTooLongException ex)
                {
                    Console.WriteLine($"Path too long: {currentDir}. Error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error accessing directory: {currentDir}. Error: {ex.Message}");
                }
            }
        }

        static bool IsDotNetAssembly(string filePath)
        {
            try
            {
                using (var stream = File.OpenRead(filePath))
                using (var peReader = new PEReader(stream))
                {
                    return peReader.HasMetadata;
                }
            }
            catch
            {
                return false;
            }
        }

        static void FindMethodCalls(string assemblyPath, string[] methodsToSearch)
        {
            try
            {
                var assembly = AssemblyDefinition.ReadAssembly(assemblyPath);

                foreach (var module in assembly.Modules)
                {
                    foreach (var type in module.GetTypes())
                    {
                        foreach (var method in type.Methods)
                        {
                            if (method.HasBody)
                            {
                                AnalyzeMethod(method, methodsToSearch, assemblyPath);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load assembly {assemblyPath}: {ex.Message}");
            }
        }

        static void AnalyzeMethod(MethodDefinition method, string[] methodsToSearch, string assemblyPath)
        {
            foreach (var instr in method.Body.Instructions)
            {
                if (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt)
                {
                    var methodOperand = instr.Operand as MethodReference;
                    if (methodOperand != null && methodsToSearch.Any(searchMethod => methodOperand.FullName.Contains(searchMethod)))
                    {
                        Console.WriteLine($"[*] Method: {method.FullName} in {assemblyPath} calls {methodOperand.FullName} at offset {instr.Offset}");
                        if (_DECOMPLIE)
                        {
                            Console.WriteLine("Decompiled Method:");
                            Console.WriteLine(DecompileMethod(method));
                            Console.WriteLine(new string('-', 80));
                        }
                        Console.WriteLine();
                        

                    }
                }
            }
        }

        static string DecompileMethod(MethodDefinition method)
        {
            var decompiler = new System.Text.StringBuilder();

            decompiler.AppendLine($"Method: {method.FullName}");
            decompiler.AppendLine("{");

            foreach (var variable in method.Body.Variables)
            {
                decompiler.AppendLine($"    var {variable.ToString}: {variable.VariableType}");
            }

            foreach (var instr in method.Body.Instructions)
            {
                decompiler.AppendLine($"    {instr}");
            }

            decompiler.AppendLine("}");

            return decompiler.ToString();
        }
    }
}
