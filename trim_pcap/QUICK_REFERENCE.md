# PCAP Large File Processing - Quick Reference

## 🚀 Quick Command Templates

### File Size Based Commands

```bash
# Small files (<500MB) - Default settings
python3 trim_pcap.py input.pcap output.pcap

# Medium files (500MB-2GB) - Optimized batching
python3 trim_pcap.py input.pcap output.pcap --batch-size 2000

# Large files (2GB-10GB) - With threading
python3 trim_pcap.py input.pcap output.pcap --batch-size 3000 --enable-threading

# Huge files (>10GB) - Maximum optimization
python3 trim_pcap.py input.pcap output.pcap --batch-size 5000 --enable-threading --quiet
```

### Memory Constrained Systems

```bash
# Low memory (2GB RAM system)
python3 trim_pcap.py input.pcap output.pcap --batch-size 500 --memory-limit 256

# Normal memory (8GB RAM system) 
python3 trim_pcap.py input.pcap output.pcap --batch-size 2000 --memory-limit 1024

# High memory (16GB+ RAM system)
python3 trim_pcap.py input.pcap output.pcap --batch-size 5000 --memory-limit 4096 --enable-threading
```

### Common Use Cases

```bash
# Network security analysis
python3 trim_pcap.py security.pcap clean.pcap --pattern "ff ff ff ff" --include-second --batch-size 4000

# Malware analysis
python3 trim_pcap.py malware.pcap filtered.pcap --ascii --pattern "MALWARE" --batch-size 2000 --verbose

# Performance testing (dry run)
python3 trim_pcap.py test.pcap /dev/null --dry-run --batch-size 3000 --enable-threading

# Forensic analysis
python3 trim_pcap.py evidence.pcap processed.pcap --batch-size 8000 --enable-threading --quiet
```

### Directory Processing

```bash
# Process all PCAP files in-place (saves with '-modified' suffix)
python3 trim_pcap.py -d /path/to/pcap/files

# Process all PCAP files to destination directory
python3 trim_pcap.py -d /path/to/source/pcaps /path/to/destination

# Directory processing with custom pattern (in-place)
python3 trim_pcap.py -d ./network_logs --pattern "45 00 01" --verbose

# High-performance directory processing to destination
python3 trim_pcap.py -d /data/captures /data/cleaned --batch-size 3000 --enable-threading

# Directory processing with ASCII pattern (in-place, dry-run)
python3 trim_pcap.py -d ./pcap_files --ascii --pattern "HTTP" --dry-run

# Large directory with memory constraints (to destination)
python3 trim_pcap.py -d ./large_pcaps ./output --batch-size 2000 --memory-limit 1024 --quiet
```

## 📊 Performance Expectations

| File Size | Command | Expected Time | Memory Usage |
|-----------|---------|---------------|--------------|
| 500MB | `--batch-size 1500` | ~30s | ~100MB |
| 2GB | `--batch-size 2000` | ~1.5min | ~200MB |
| 5GB | `--batch-size 3000 --enable-threading` | ~3min | ~300MB |
| 10GB | `--batch-size 5000 --enable-threading` | ~5min | ~400MB |
| 25GB | `--batch-size 8000 --enable-threading --quiet` | ~10min | ~500MB |

## 🔧 Troubleshooting

### If processing is too slow:
```bash
# Increase batch size and enable threading
--batch-size 5000 --enable-threading --quiet
```

### If running out of memory:
```bash
# Reduce batch size and set memory limit
--batch-size 500 --memory-limit 512
```

### If need to monitor progress:
```bash
# Add verbose progress reporting
--verbose --progress-interval 5000
```

### If testing before full processing:
```bash
# Use dry-run mode
--dry-run --verbose
```

### 🩺 Advanced Troubleshooting

#### Unexpected Size Reduction Issues:
```bash
# Enable troubleshooting mode for detailed analysis
python3 trim_pcap.py input.pcap output.pcap --troubleshoot --sample-packets 100

# Validate pattern matching with detailed output
python3 trim_pcap.py input.pcap output.pcap --validate-patterns --verbose --dry-run

# Check first few packets for pattern analysis
python3 trim_pcap.py input.pcap output.pcap --sample-packets 50 --verbose --dry-run
```

#### Pattern Effectiveness Testing:
```bash
# Test different patterns to find optimal one
for pattern in "45 00 01" "ff ff" "80 00 45" "08 00 45 00"; do
    echo "Testing pattern: $pattern"
    python3 trim_pcap.py test.pcap /dev/null --dry-run --pattern "$pattern" --troubleshoot
    echo "---"
done
```

#### Diagnostic Output Analysis:
The enhanced diagnostic output will show:
- ✅ **Consistent reduction**: Theoretical vs actual file size reduction match
- ⚠️ **Potential issues**: Large discrepancies between expected and actual reduction
- 📊 **Modification efficiency**: Percentage of packets that contained dual patterns
- 🔍 **Pattern validation**: Detailed packet-by-packet analysis

## 📋 Copy-Paste Commands

### Production Ready Commands

```bash
# Standard production processing
python3 trim_pcap.py "${INPUT_FILE}" "${OUTPUT_FILE}" \
  --batch-size 3000 \
  --enable-threading \
  --progress-interval 15000 \
  --memory-limit 2048 \
  --log-level INFO

# High-performance processing  
python3 trim_pcap.py "${INPUT_FILE}" "${OUTPUT_FILE}" \
  --batch-size 8000 \
  --enable-threading \
  --progress-interval 50000 \
  --memory-limit 4096 \
  --quiet

# Conservative processing (limited resources)
python3 trim_pcap.py "${INPUT_FILE}" "${OUTPUT_FILE}" \
  --batch-size 800 \
  --memory-limit 512 \
  --progress-interval 5000 \
  --log-level WARNING
```

### Batch Processing Script Template

```bash
#!/bin/bash
# Option 1: Process multiple large PCAP files individually

INPUT_DIR="/path/to/pcap/files"
OUTPUT_DIR="/path/to/output" 
PATTERN="45 00 01"  # Customize pattern

for pcap_file in "${INPUT_DIR}"/*.pcap; do
    basename=$(basename "$pcap_file" .pcap)
    echo "Processing: $basename"
    
    python3 trim_pcap.py "$pcap_file" "${OUTPUT_DIR}/${basename}_processed.pcap" \
        --pattern "$PATTERN" \
        --batch-size 3000 \
        --enable-threading \
        --progress-interval 20000 \
        --memory-limit 2048 \
        --quiet
        
    if [ $? -eq 0 ]; then
        echo "✓ Success: $basename"
    else
        echo "✗ Failed: $basename"
    fi
done
```

```bash
#!/bin/bash
# Option 2: Use built-in directory processing (RECOMMENDED)

INPUT_DIR="/path/to/pcap/files"
OUTPUT_DIR="/path/to/output"  # Optional - omit for in-place processing
PATTERN="45 00 01"  # Customize pattern

echo "Processing all PCAP files in directory: $INPUT_DIR"

# Process to destination directory
python3 trim_pcap.py -d "$INPUT_DIR" "$OUTPUT_DIR" \
    --pattern "$PATTERN" \
    --batch-size 3000 \
    --enable-threading \
    --progress-interval 20000 \
    --memory-limit 2048 \
    --verbose

# OR process in-place with '-modified' suffix
# python3 trim_pcap.py -d "$INPUT_DIR" \
#     --pattern "$PATTERN" \
#     --batch-size 3000 \
#     --enable-threading \
#     --progress-interval 20000 \
#     --memory-limit 2048 \
#     --verbose

if [ $? -eq 0 ]; then
    echo "✓ Directory processing completed successfully"
else
    echo "✗ Directory processing encountered errors"
fi
```

## 💡 Pro Tips

1. **Always test with dry-run first** on large files
2. **Monitor memory usage** with `--memory-limit` 
3. **Use threading** for files >1GB and batch sizes >1000
4. **Increase progress interval** for huge files to reduce overhead
5. **Use quiet mode** for production processing to improve performance
6. **Set appropriate batch size** based on available RAM
7. **Consider disk space** - output files may be significantly smaller
8. **Use directory processing (-d)** for batch operations instead of shell loops
9. **Create destination directory** - it will be created automatically if it doesn't exist
10. **Mixed file extensions** - supports .pcap, .pcapng, and .cap files automatically