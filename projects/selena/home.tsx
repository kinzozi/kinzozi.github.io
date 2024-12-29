import { useState } from "react";
import { FileUpload } from "../components/FileUpload";
import { CodeInput } from "../components/CodeInput";
import { AnalysisResults } from "../components/AnalysisResults";
import { ExploitWorkbench } from "../components/ExploitWorkbench";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { useMutation } from "@tanstack/react-query";
import { analyzeCode } from "../lib/api";

export default function Home() {
  const [code, setCode] = useState("");
  const [selectedVulnerability, setSelectedVulnerability] = useState<null | {
    severity: 'high' | 'medium' | 'low';
    description: string;
    type: string;
    cwe_id: string;
    mitigation: string;
    cvss_score?: number;
    affected_functions?: string[];
    exploitation_scenario?: string;
    references?: string[];
  }>(null);
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [results, setResults] = useState<null | {
    summary: string;
    patterns: string[];
    strings: string[];
    vulnerabilities: Array<{
      severity: 'high' | 'medium' | 'low';
      description: string;
      type: string;
      cwe_id: string;
      mitigation: string;
      cvss_score?: number;
      affected_functions?: string[];
      exploitation_scenario?: string;
      references?: string[];
    }>;
    advanced_analysis?: {
      execution_paths: string[];
      api_calls: string[];
      crypto_usage: string[];
      network_activity: string[];
      binary_protections?: {
        [key: string]: string;
      };
    };
  }>(null);
  const { toast } = useToast();

  const analyzeMutation = useMutation({
    mutationFn: analyzeCode,
    onSuccess: (data) => {
      setResults(data);
    },
    onError: () => {
      toast({
        title: "Analysis Failed",
        description: "There was an error analyzing your code. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleAnalyze = () => {
    if (!code) {
      toast({
        title: "No Input",
        description: "Please upload a file or paste code to analyze.",
        variant: "destructive",
      });
      return;
    }

    // For regular code analysis
    analyzeMutation.mutate({ code });
  };

  return (
    <div className="min-h-screen bg-background text-foreground font-sans">
      <header className="border-b p-4">
        <div className="container mx-auto">
          <h1 className="text-2xl font-bold text-primary">Selena Oracle</h1>
          <p className="text-muted-foreground">AI-Powered Reverse Engineering Tool</p>
        </div>
      </header>

      <main className="container mx-auto p-4 space-y-8">
        <Tabs defaultValue="upload" className="w-full">
          <TabsList className="grid w-full max-w-md mx-auto grid-cols-3">
            <TabsTrigger value="upload">Upload File</TabsTrigger>
            <TabsTrigger value="paste">Paste Code</TabsTrigger>
            <TabsTrigger value="workbench" disabled={!selectedVulnerability}>Exploit Workbench</TabsTrigger>
          </TabsList>
          <TabsContent value="upload">
            <div className="space-y-6">
              <FileUpload onCodeLoaded={(data) => {
                try {
                  // Try to parse as JSON first (for binary analysis results)
                  const parsedData = JSON.parse(data);
                  
                  // Validate the structure matches our expected format
                  if (typeof parsedData === 'object' && parsedData !== null) {
                    const isValidAnalysis = parsedData.summary && 
                      Array.isArray(parsedData.vulnerabilities) &&
                      Array.isArray(parsedData.patterns) &&
                      Array.isArray(parsedData.strings);

                    if (isValidAnalysis) {
                      // Validate vulnerability data structure with stronger type checking
                      const validatedVulnerabilities = parsedData.vulnerabilities.map((vuln: any) => {
                        // Validate severity is one of the allowed values
                        const severity = String(vuln.severity || 'medium').toLowerCase();
                        if (!['high', 'medium', 'low'].includes(severity)) {
                          throw new Error(`Invalid severity value: ${severity}`);
                        }

                        return {
                          severity: severity as 'high' | 'medium' | 'low',
                          description: String(vuln.description || 'No description provided'),
                          type: String(vuln.type || 'Unknown'),
                          cwe_id: String(vuln.cwe_id || 'CWE-0'),
                          mitigation: String(vuln.mitigation || 'No mitigation provided'),
                          cvss_score: typeof vuln.cvss_score === 'number' ? vuln.cvss_score : undefined,
                          affected_functions: Array.isArray(vuln.affected_functions) ? vuln.affected_functions.map(String) : [],
                          exploitation_scenario: vuln.exploitation_scenario ? String(vuln.exploitation_scenario) : undefined,
                          references: Array.isArray(vuln.references) ? vuln.references.map(String) : []
                        };
                      });

                      // Set validated results with strong type checking
                      setResults({
                        summary: String(parsedData.summary),
                        patterns: Array.isArray(parsedData.patterns) ? parsedData.patterns.map(String) : [],
                        strings: Array.isArray(parsedData.strings) ? parsedData.strings.map(String) : [],
                        vulnerabilities: validatedVulnerabilities,
                        advanced_analysis: parsedData.advanced_analysis ? {
                          execution_paths: Array.isArray(parsedData.advanced_analysis.execution_paths) 
                            ? parsedData.advanced_analysis.execution_paths.map(String) : [],
                          api_calls: Array.isArray(parsedData.advanced_analysis.api_calls) 
                            ? parsedData.advanced_analysis.api_calls.map(String) : [],
                          crypto_usage: Array.isArray(parsedData.advanced_analysis.crypto_usage) 
                            ? parsedData.advanced_analysis.crypto_usage.map(String) : [],
                          network_activity: Array.isArray(parsedData.advanced_analysis.network_activity) 
                            ? parsedData.advanced_analysis.network_activity.map(String) : []
                        } : undefined
                      });
                      return;
                    }
                  }
                  // If it's not a valid analysis result, treat as code
                  setCode(data);
                } catch (e) {
                  // If parsing fails or validation throws an error, treat as regular code
                  console.warn('Failed to parse as analysis result:', e);
                  setCode(data);
                }
              }} />
              <div className="flex justify-center">
                <Button 
                  size="lg"
                  onClick={handleAnalyze}
                  disabled={analyzeMutation.isPending || !code}
                >
                  {analyzeMutation.isPending ? "Analyzing..." : "Analyze Code"}
                </Button>
              </div>
            </div>
          </TabsContent>
          <TabsContent value="workbench">
            {selectedVulnerability ? (
              <ExploitWorkbench 
                vulnerability={selectedVulnerability}
                binaryFile={binaryFile}
              />
            ) : (
              <div className="text-center py-8">
                <p className="text-muted-foreground">
                  Select a vulnerability from the analysis results to start testing exploits.
                </p>
              </div>
            )}
          </TabsContent>
          <TabsContent value="paste">
            <div className="space-y-6">
              <CodeInput code={code} onCodeChange={setCode} />
              <div className="flex justify-center">
                <Button 
                  size="lg"
                  onClick={handleAnalyze}
                  disabled={analyzeMutation.isPending || !code}
                >
                  {analyzeMutation.isPending ? "Analyzing..." : "Analyze Code"}
                </Button>
              </div>
            </div>
          </TabsContent>
        </Tabs>

        {results && (
          <div className="space-y-8">
            <AnalysisResults 
              results={results} 
              onSendToWorkbench={(vuln) => {
                setSelectedVulnerability(vuln);
                toast({
                  title: "Vulnerability Selected",
                  description: "Vulnerability sent to exploit workbench for testing.",
                });
              }}
            />
          </div>
        )}
      </main>
    </div>
  );
}
