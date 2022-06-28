package helpers

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

/*
 * The helpers in this file gives the ability to hold all the known kernel symbols.
 * the package parse the /proc/kallsyms file that hold the known kernel symbol
 *
 * The KernelSymbolTable type holds map of all the kernel symbols with a key which is the kernel object owner and the name with under-case between them
 * which means that symbolMap looks like [objectOwner_objectname{SymbolData}, objectOwner_objectname{SymbolData}, etc...]
 * the key naming is because sometimes kernel symbols can have the same name or the same address which prevents to key the map with only one of them
 *
 */

type KernelSymbolTable struct {
	symbolMap   map[string]KernelSymbol
	initialized bool
}

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}

/* NewKernelSymbolsMap initiates  the kernel symbol map by parsing the /proc/kallsyms file.
 * each line contains the symbol's address, segment type, name, module owner (which can be empty in case the symbol is owned by the system)
 * Note: the key of the map is the symbol owner and the symbol name (with undercase between them)
 */
func NewKernelSymbolsMap() (*KernelSymbolTable, error) {
	var KernelSymbols = KernelSymbolTable{}
	KernelSymbols.symbolMap = make(map[string]KernelSymbol)
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("could not open /proc/kallsyms: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		//if the line is less than 3 words, we can't parse it (one or more fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		symbolType := line[1]
		symbolName := line[2]

		symbolOwner := "system"
		if len(line) > 3 {
			// When a symbol is contained in a kernel module, it will be specified
			// within square brackets, otherwise it's part of the system
			symbolOwner = line[3]
			symbolOwner = strings.TrimPrefix(symbolOwner, "[")
			symbolOwner = strings.TrimSuffix(symbolOwner, "]")
		}

		symbolKey := fmt.Sprintf("%s_%s", symbolOwner, symbolName)
		KernelSymbols.symbolMap[symbolKey] = KernelSymbol{symbolName, symbolType, symbolAddr, symbolOwner}
	}
	KernelSymbols.initialized = true
	return &KernelSymbols, nil
}

// TextSegmentContains checks if a given address is in the kernel text segment
// by comparing it to the kernel text segment address boundaries
func (k *KernelSymbolTable) TextSegmentContains(addr uint64) (bool, error) {
	if !k.initialized {
		return false, errors.New("kernel symbols map isnt initialized")
	}
	stext, err := k.GetSymbolByName("system", "_stext")
	if err != nil {
		return false, err
	}
	etext, err := k.GetSymbolByName("system", "_etext")
	if err != nil {
		return false, err
	}
	return ((addr >= stext.Address) && (addr < etext.Address)), nil
}

// GetSymbolByName returns a symbol by a given name and owner
func (k *KernelSymbolTable) GetSymbolByName(owner string, name string) (*KernelSymbol, error) {
	key := fmt.Sprintf("%s_%s", owner, name)
	symbol, exist := k.symbolMap[key]
	if exist {
		return &symbol, nil
	}
	return nil, fmt.Errorf("symbol not found: %s_%s", owner, name)
}

// GetSymbolByAddr returns a symbol by a given address
func (k *KernelSymbolTable) GetSymbolByAddr(addr uint64) (*KernelSymbol, error) {
	for _, Symbol := range k.symbolMap {
		if Symbol.Address == addr {
			return &Symbol, nil
		}
	}
	return nil, fmt.Errorf("symbol not found at address: 0x%x", addr)
}
