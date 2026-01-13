package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/scrtlabs/reproduce-mr/internal"
)

type measurementOutput struct {
	MRTD         string `json:"mrtd"`
	RTMR0        string `json:"rtmr0"`
	RTMR1        string `json:"rtmr1"`
	RTMR2        string `json:"rtmr2"`
	RTMR3        string `json:"rtmr3"`
	MrAggregated string `json:"mr_aggregated"`
	MrImage      string `json:"mr_image"`
}

var knownKeyProviders = map[string]string{
	"sgx-v0": "0x4888adb026ff91c1320c4f544a9f5d9e0561e13fc64947a10aa1556d0071b2cc",
	"none":   "0x3369c4d32b9f1320ebba5ce9892a283127b7e96e1d511d7f292e5d9ed2c10b8c",
}

// parseMemorySize parses a human readable memory size (e.g., "1G", "512M") into megabytes
func parseMemorySize(size string) (uint64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))
	if len(size) == 0 {
		return 0, fmt.Errorf("empty memory size")
	}

	// Get the unit (last character)
	unit := size[len(size)-1:]
	// Get the number (everything except the last character)
	numStr := size[:len(size)-1]

	// Parse the number
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size number: %v", err)
	}

	// Convert to megabytes based on unit
	switch unit {
	case "G":
		return num * 1024, nil // Convert GB to MB
	case "M":
		return num, nil // Already in MB
	default:
		return 0, fmt.Errorf("invalid memory unit '%s', must be one of: G, M", unit)
	}
}

type memoryValue uint64

func (m *memoryValue) String() string {
	mb := uint64(*m)
	const (
		GB = 1024 // in MB
	)

	if mb >= GB && mb%GB == 0 {
		return fmt.Sprintf("%dG", mb/GB)
	}
	return fmt.Sprintf("%dM", mb)
}

func (m *memoryValue) Set(value string) error {
	mb, err := parseMemorySize(value)
	if err != nil {
		return err
	}
	*m = memoryValue(mb)
	return nil
}

func main() {
	const defaultMrKeyProvider = "0x0000000000000000000000000000000000000000000000000000000000000000"
	var (
		fwPath            string
		kernelPath        string
		initrdPath        string
		rootfsPath        string
		dockerComposePath string
		dockerFilesPath   string
		memorySize        memoryValue = 2048 // 2G default (in MB)
		cpuCountUint      uint
		tcbver            uint
		kernelCmdline     string
		jsonOutput        bool
		mrKeyProvider     string = defaultMrKeyProvider
		templatesPath     string
	)

	flag.StringVar(&fwPath, "fw", "", "Path to firmware file")
	flag.StringVar(&kernelPath, "kernel", "", "Path to kernel file")
	flag.StringVar(&initrdPath, "initrd", "", "Path to initrd file")
	flag.StringVar(&rootfsPath, "rootfs", "", "Path to rootfs file")
	flag.StringVar(&dockerComposePath, "dockercompose", "", "Path to docker compose file")
	flag.StringVar(&dockerFilesPath, "dockerfiles", "", "Path to docker files file")
	flag.Var(&memorySize, "memory", "Memory size (e.g., 512M, 1G, 2G)")
	flag.UintVar(&tcbver, "tcbver", 0, "TCB version (currently only 6 and 7 are supported)")
	flag.UintVar(&cpuCountUint, "cpu", 1, "Number of CPUs")
	flag.StringVar(&kernelCmdline, "cmdline", "", "Kernel command line")
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.StringVar(&mrKeyProvider, "mrkp", defaultMrKeyProvider, "Measurement of key provider")
	flag.StringVar(&templatesPath, "templates", "", "Path to templates directory")
	flag.Parse()

	// If the mrKeyProvider is in the knownKeyProviders, replace it with the value
	if knownKeyProvider, ok := knownKeyProviders[mrKeyProvider]; ok {
		mrKeyProvider = knownKeyProvider
	}

	if templatesPath == "" {
		fmt.Println("Error: templates path is required")
		flag.Usage()
		os.Exit(1)
	}

	if fwPath == "" || kernelPath == "" {
		fmt.Println("Error: firmware and kernel paths are required")
		flag.Usage()
		os.Exit(1)
	}

	// Read files
	fwData, err := os.ReadFile(fwPath)
	if err != nil {
		fmt.Printf("Error reading firmware file: %v\n", err)
		os.Exit(1)
	}

	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		fmt.Printf("Error reading kernel file: %v\n", err)
		os.Exit(1)
	}

	var initrdData []byte
	if initrdPath != "" {
		initrdData, err = os.ReadFile(initrdPath)
		if err != nil {
			fmt.Printf("Error reading initrd file: %v\n", err)
			os.Exit(1)
		}
	}

	var rootfsData []byte
	if rootfsPath != "" {
		rootfsData, err = os.ReadFile(rootfsPath)
		if err != nil {
			fmt.Printf("Error reading rootfs file: %v\n", err)
			os.Exit(1)
		}
	}

	var dockerComposeData []byte
	if dockerComposePath != "" {
		dockerComposeData, err = os.ReadFile(dockerComposePath)
		if err != nil {
			fmt.Printf("Error reading docker compose file: %v\n", err)
			os.Exit(1)
		}
	}

	var dockerFilesData []byte
	if dockerFilesPath != "" {
		dockerFilesData, err = os.ReadFile(dockerFilesPath)
		if err != nil {
			fmt.Printf("Error reading docker files file: %v\n", err)
			os.Exit(1)
		}
	}
	// Calculate measurements
	measurements, err := internal.MeasureTdxQemu(fwData, kernelData, initrdData, rootfsData, dockerComposeData, dockerFilesData, uint64(memorySize), uint8(cpuCountUint), kernelCmdline, templatesPath, uint8(tcbver))
	if err != nil {
		fmt.Printf("Error calculating measurements: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output := measurementOutput{
			MRTD:         fmt.Sprintf("%x", measurements.MRTD),
			RTMR0:        fmt.Sprintf("%x", measurements.RTMR0),
			RTMR1:        fmt.Sprintf("%x", measurements.RTMR1),
			RTMR2:        fmt.Sprintf("%x", measurements.RTMR2),
			RTMR3:        fmt.Sprintf("%x", measurements.RTMR3),
			MrAggregated: measurements.CalculateMrAggregated(mrKeyProvider),
			MrImage:      measurements.CalculateMrImage(),
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Printf("Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("MRTD: %x\n", measurements.MRTD)
		fmt.Printf("RTMR0: %x\n", measurements.RTMR0)
		fmt.Printf("RTMR1: %x\n", measurements.RTMR1)
		fmt.Printf("RTMR2: %x\n", measurements.RTMR2)
		fmt.Printf("RTMR3: %x\n", measurements.RTMR3)
		fmt.Printf("MR_AGGREGATED: %s\n", measurements.CalculateMrAggregated(mrKeyProvider))
		fmt.Printf("MR_IMAGE: %s\n", measurements.CalculateMrImage())
	}
}
