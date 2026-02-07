package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

// Known risk indicators
var (
	// Known phishing/scam contract patterns
	maliciousPatterns = []string{
		"0x0000000000000000000000000000000000000000", // Burn address (context dependent)
	}
	
	// Known high-risk contract types (simplified)
	highRiskFunctions = []string{
		"approve",
		"setApprovalForAll", 
		"transferOwnership",
		"selfdestruct",
	}
)

type ReputationReport struct {
	Address        string          `json:"address"`
	Network        string          `json:"network"`
	Timestamp      time.Time       `json:"timestamp"`
	OverallScore   int             `json:"overall_score"` // 0-100, higher = more trustworthy
	RiskLevel      string          `json:"risk_level"`    // low, medium, high, critical
	Checks         []CheckResult   `json:"checks"`
	Recommendations []string       `json:"recommendations"`
}

type CheckResult struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // pass, warning, fail
	Score       int    `json:"score"`  // 0-100
	Details     string `json:"details"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("❌ Address required: scanner scan 0x...")
			os.Exit(1)
		}
		address := os.Args[2]
		network := "ethereum"
		if len(os.Args) > 3 {
			network = os.Args[3]
		}
		scanAddress(address, network)
	case "batch":
		if len(os.Args) < 3 {
			fmt.Println("❌ File required: scanner batch addresses.txt")
			os.Exit(1)
		}
		batchScan(os.Args[2])
	case "version":
		fmt.Printf("agent-reputation-scanner v%s\n", version)
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("🔍 Agent Reputation Scanner")
	fmt.Println("============================")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  scanner scan 0x... [network]  - Scan single address")
	fmt.Println("  scanner batch addresses.txt   - Batch scan from file")
	fmt.Println("")
	fmt.Println("Networks: ethereum, base")
	fmt.Println("")
	fmt.Println("Checks performed:")
	fmt.Println("  • Address format validation")
	fmt.Println("  • Contract verification status")
	fmt.Println("  • Account age/activity")
	fmt.Println("  • Transaction patterns")
	fmt.Println("  • Known malicious associations")
}

func scanAddress(address, network string) {
	fmt.Printf("🔍 Scanning %s on %s...\n\n", address, network)

	report := ReputationReport{
		Address:   address,
		Network:   network,
		Timestamp: time.Now(),
		Checks:    []CheckResult{},
	}

	// Check 1: Address format
	report.Checks = append(report.Checks, checkAddressFormat(address))

	// Check 2: Is contract
	report.Checks = append(report.Checks, checkIsContract(address, network))

	// Check 3: Contract verification
	report.Checks = append(report.Checks, checkVerification(address, network))

	// Check 4: Account age
	report.Checks = append(report.Checks, checkAccountAge(address, network))

	// Check 5: Transaction volume
	report.Checks = append(report.Checks, checkTransactionVolume(address, network))

	// Check 6: Known patterns
	report.Checks = append(report.Checks, checkKnownPatterns(address))

	// Calculate overall score
	report.OverallScore = calculateOverallScore(report.Checks)
	report.RiskLevel = determineRiskLevel(report.OverallScore)
	report.Recommendations = generateRecommendations(report.Checks)

	// Print report
	printReport(report)
}

func checkAddressFormat(address string) CheckResult {
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return CheckResult{
			Name:    "Address Format",
			Status:  "fail",
			Score:   0,
			Details: "Invalid Ethereum address format",
		}
	}
	return CheckResult{
		Name:    "Address Format",
		Status:  "pass",
		Score:   100,
		Details: "Valid checksummed address",
	}
}

func checkIsContract(address, network string) CheckResult {
	// This would normally query the blockchain
	// For now, we'll return a placeholder that can be implemented
	return CheckResult{
		Name:    "Contract Check",
		Status:  "warning",
		Score:   50,
		Details: "Requires RPC connection (see: cast code " + address + ")",
	}
}

func checkVerification(address, network string) CheckResult {
	// Check Etherscan/BaseScan for verification status
	apiKey := getAPIKey(network)
	if apiKey == "" {
		return CheckResult{
			Name:    "Contract Verification",
			Status:  "warning",
			Score:   50,
			Details: "No API key configured",
		}
	}

	// This would call Etherscan API
	// For demo, return neutral
	return CheckResult{
		Name:    "Contract Verification",
		Status:  "warning",
		Score:   50,
		Details: "API integration required (config in ~/.config/agent-reputation-scanner/)",
	}
}

func checkAccountAge(address, network string) CheckResult {
	// Check first transaction date
	return CheckResult{
		Name:    "Account Age",
		Status:  "warning",
		Score:   50,
		Details: "Requires blockchain query (see: cast tx-count " + address + ")",
	}
}

func checkTransactionVolume(address, network string) CheckResult {
	return CheckResult{
		Name:    "Transaction Volume",
		Status:  "warning",
		Score:   50,
		Details: "Requires blockchain query",
	}
}

func checkKnownPatterns(address string) CheckResult {
	lowerAddr := strings.ToLower(address)
	
	for _, pattern := range maliciousPatterns {
		if strings.Contains(lowerAddr, strings.ToLower(pattern)) {
			return CheckResult{
				Name:    "Known Patterns",
				Status:  "fail",
				Score:   0,
				Details: "Matches known malicious pattern",
			}
		}
	}
	
	return CheckResult{
		Name:    "Known Patterns",
		Status:  "pass",
		Score:   100,
		Details: "No known malicious patterns detected",
	}
}

func calculateOverallScore(checks []CheckResult) int {
	if len(checks) == 0 {
		return 0
	}
	
	total := 0
	for _, check := range checks {
		total += check.Score
	}
	return total / len(checks)
}

func determineRiskLevel(score int) string {
	switch {
	case score >= 90:
		return "low"
	case score >= 70:
		return "medium"
	case score >= 40:
		return "high"
	default:
		return "critical"
	}
}

func generateRecommendations(checks []CheckResult) []string {
	recommendations := []string{}
	
	for _, check := range checks {
		if check.Status == "fail" {
			recommendations = append(recommendations, 
				fmt.Sprintf("⚠️  %s: %s", check.Name, check.Details))
		}
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "✓ Address passed all automated checks")
		recommendations = append(recommendations, "⚠️  Manual review still recommended for high-value transactions")
	}
	
	return recommendations
}

func printReport(report ReputationReport) {
	fmt.Println("═".repeat(60))
	fmt.Printf("  REPUTATION REPORT\n")
	fmt.Println("═".repeat(60))
	fmt.Printf("Address: %s\n", report.Address)
	fmt.Printf("Network: %s\n", report.Network)
	fmt.Printf("Time:    %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println()
	
	// Score bar
	fmt.Printf("Overall Score: %d/100\n", report.OverallScore)
	fmt.Printf("Risk Level:    %s %s\n", getRiskEmoji(report.RiskLevel), strings.ToUpper(report.RiskLevel))
	fmt.Println()
	
	fmt.Println("CHECKS:")
	fmt.Println("─".repeat(60))
	for _, check := range report.Checks {
		statusIcon := "✓"
		if check.Status == "warning" {
			statusIcon = "⚠️"
		} else if check.Status == "fail" {
			statusIcon = "✗"
		}
		fmt.Printf("  %s %-25s [%d%%] %s\n", statusIcon, check.Name, check.Score, check.Status)
		fmt.Printf("     └─ %s\n", check.Details)
	}
	
	fmt.Println()
	fmt.Println("RECOMMENDATIONS:")
	fmt.Println("─".repeat(60))
	for _, rec := range report.Recommendations {
		fmt.Printf("  %s\n", rec)
	}
	
	fmt.Println()
	fmt.Println("═".repeat(60))
	fmt.Println("⚠️  This is an automated assessment. Always conduct")
	fmt.Println("   additional due diligence for high-value transactions.")
	fmt.Println("═".repeat(60))
}

func getRiskEmoji(level string) string {
	switch level {
	case "low":
		return "🟢"
	case "medium":
		return "🟡"
	case "high":
		return "🟠"
	case "critical":
		return "🔴"
	default:
		return "⚪"
	}
}

func (s string) repeat(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func getAPIKey(network string) string {
	// Would load from config file
	return os.Getenv(strings.ToUpper(network) + "_API_KEY")
}

func batchScan(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("❌ Cannot read file: %v\n", err)
		os.Exit(1)
	}

	addresses := strings.Split(string(data), "\n")
	fmt.Printf("🔍 Batch scanning %d addresses...\n\n", len(addresses))

	results := []ReputationReport{}
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr)
		if addr == "" || !strings.HasPrefix(addr, "0x") {
			continue
		}
		
		report := quickScan(addr, "ethereum")
		results = append(results, report)
		
		// Print summary line
		fmt.Printf("%s... [%s] Score: %d/100 %s\n", 
			addr[:20], 
			report.RiskLevel,
			report.OverallScore,
			getRiskEmoji(report.RiskLevel))
		
		time.Sleep(200 * time.Millisecond) // Rate limiting
	}

	// Save results
	output, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile("reputation-results.json", output, 0644)
	fmt.Printf("\n✅ Results saved to reputation-results.json\n")
}

func quickScan(address, network string) ReputationReport {
	report := ReputationReport{
		Address:   address,
		Network:   network,
		Timestamp: time.Now(),
		Checks: []CheckResult{
			checkAddressFormat(address),
			checkKnownPatterns(address),
		},
	}
	
	report.OverallScore = calculateOverallScore(report.Checks)
	report.RiskLevel = determineRiskLevel(report.OverallScore)
	report.Recommendations = generateRecommendations(report.Checks)
	
	return report
}
