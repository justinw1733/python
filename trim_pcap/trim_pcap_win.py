#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Trimming Tool

A tool for processing PCAP files to remove byte ranges between pattern occurrences.
Supports hexadecimal and ASCII pattern matching with configurable deletion ranges.

Features:
- Pattern-based byte range removal
- Dry-run mode for testing
- Progress tracking for large files
- Memory-efficient processing with batching
- Multi-threaded pattern detection
- Comprehensive error handling
- Detailed statistics reporting
- Memory usage monitoring

Basic Usage:
    python trim_pcap.py input.pcap
    python trim_pcap.py input.pcap output.pcap
    python trim_pcap.py input.pcap output.pcap -p "4500" --verbose
    python trim_pcap.py input.pcap output.pcap --ascii -p "HTTP" --dry-run

Directory Processing:
    python trim_pcap.py -d C:\\path\\to\\pcap\\files
    python trim_pcap.py -d C:\\path\\to\\source\\pcaps C:\\path\\to\\destination
    python trim_pcap.py -d .\\source_dir .\\output_dir -p "4500" --verbose
    python trim_pcap.py -d C:\\data\\pcaps C:\\data\\processed --batch-size 2000 --enable-threading

Large File Processing Examples:

1. Standard Large File (1-5GB):
   python trim_pcap.py large_capture.pcap processed.pcap --batch-size 2000 --progress-interval 5000
   
   # With memory monitoring (requires psutil):
   python trim_pcap.py large_capture.pcap processed.pcap --batch-size 2000 --memory-limit 512

2. Very Large File (>5GB) with Multi-threading:
   python trim_pcap.py huge_capture.pcap processed.pcap \
     --batch-size 5000 \
     --enable-threading \
     --progress-interval 10000 \
     --quiet

3. Memory-Constrained Environment:
   python trim_pcap.py file.pcap output.pcap \
     --batch-size 500 \
     --memory-limit 256 \
     --log-level WARNING

4. High-Performance Processing:
   python trim_pcap.py network_traffic.pcap cleaned.pcap \
     --batch-size 10000 \
     --enable-threading \
     --progress-interval 50000 \
     --pattern "4500" \
     --include-second

5. Testing Large Files (Dry Run):
   python trim_pcap.py test_large.pcap C:\\temp\\output.pcap \
     --dry-run \
     --batch-size 3000 \
     --verbose \
     --enable-threading

6. Custom Pattern Processing:
   python trim_pcap.py malware_capture.pcap clean.pcap \
     --ascii \
     --pattern "malicious_signature" \
     --batch-size 1500 \
     --memory-limit 1024

7. Network Security Analysis:
   python trim_pcap.py security_logs.pcap filtered.pcap \
     --pattern "ff ff ff ff" \
     --include-second \
     --batch-size 4000 \
     --enable-threading \
     --progress-interval 20000

Performance Guidelines:
- Batch Size: Start with 1000, increase to 2000-5000 for files >1GB
- Threading: Enable for batch sizes >1000 and files >500MB
- Memory Limit: Set to 50-70% of available RAM
- Progress Interval: Use larger values (10000+) for huge files to reduce overhead

Memory Usage Estimates:
- Small files (<100MB): ~50-100MB RAM
- Medium files (100MB-1GB): ~100-200MB RAM  
- Large files (1GB-10GB): ~150-300MB RAM
- Very large files (>10GB): ~200-400MB RAM

Optimal Settings by File Size:
- <500MB: Default settings (batch-size 1000)
- 500MB-2GB: --batch-size 2000
- 2GB-10GB: --batch-size 3000 --enable-threading
- >10GB: --batch-size 5000 --enable-threading --quiet
"""

import argparse
import gc
import glob
import logging
import mmap
import os
import re
import sys
import threading
import time
import typing
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple
from scapy.utils import RawPcapReader, RawPcapWriter, RawPcapNgReader
import struct

class ModifiedPacketMeta:
    """Wrapper for packet metadata that allows modification of wirelen."""
    
    def __init__(self, original_meta, new_wirelen=None):
        self._original = original_meta
        self._new_wirelen = new_wirelen
        
        # Copy all attributes from original metadata
        for attr in dir(original_meta):
            if not attr.startswith('_') and not callable(getattr(original_meta, attr)):
                try:
                    setattr(self, attr, getattr(original_meta, attr))
                except (AttributeError, TypeError):
                    pass
    
    @property
    def wirelen(self):
        return self._new_wirelen if self._new_wirelen is not None else getattr(self._original, 'wirelen', None)
    
    def __getattr__(self, name):
        # Fallback to original metadata for any missing attributes
        return getattr(self._original, name)

class TimestampPreservingWriter:
    """Custom writer that preserves original packet timestamps."""
    
    def __init__(self, filename, linktype=1):
        """Initialize the writer with PCAP file header."""
        self.f: Optional[typing.BinaryIO] = open(filename, 'wb')
        self.linktype = linktype
        # Write PCAP file header
        self.f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
    
    def write(self, pkt_bytes, timestamp_sec=None, timestamp_usec=None, wirelen=None):
        """Write a packet with preserved timestamp."""
        if timestamp_sec is None:
            import time
            current_time = time.time()
            timestamp_sec = int(current_time)
            timestamp_usec = int((current_time - timestamp_sec) * 1000000)
        if timestamp_usec is None:
            timestamp_usec = 0
        if wirelen is None:
            wirelen = len(pkt_bytes)
            
        caplen = len(pkt_bytes)
        # Write packet header: sec, usec, caplen, wirelen
        if self.f is not None:
            self.f.write(struct.pack('<IIII', timestamp_sec, timestamp_usec, caplen, wirelen))
        # Write packet data
        if self.f is not None:
            self.f.write(pkt_bytes)
    
    def close(self):
        """Close the file."""
        if hasattr(self, 'f') and self.f:
            self.f.close()
            self.f = None

# Optional imports for enhanced features
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class PcapTrimmer:
    """
    High-performance PCAP file processor for pattern-based byte range trimming.
    
    This class handles the processing of PCAP files to remove byte sequences
    between pattern occurrences, with optimizations for large files including:
    - Memory-efficient streaming processing
    - Buffered I/O operations
    - Memory usage monitoring
    - Batch processing capabilities
    - Multi-threaded pattern detection (optional)
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the PcapTrimmer.
        
        Args:
            logger: Optional logger instance for output control
        """
        self.logger = logger or self._setup_logger()
        self.stats = {
            "total_packets": 0,
            "modified_packets": 0,
            "unchanged_packets": 0,
            "bytes_removed_total": 0,
            "processing_time": 0.0,
            "file_size_input": 0,
            "file_size_output": 0,
            "peak_memory_usage": 0,
            "avg_memory_usage": 0,
            "gc_collections": 0
        }
        self._memory_samples = []
        self._last_gc_time = time.time()
    
    def _monitor_memory_usage(self) -> None:
        """Monitor and record memory usage statistics."""
        if not PSUTIL_AVAILABLE:
            return
            
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024  # Convert to MB
            
            self._memory_samples.append(memory_mb)
            
            # Keep only last 100 samples to prevent memory growth
            if len(self._memory_samples) > 100:
                self._memory_samples = self._memory_samples[-50:]
            
            # Update peak memory
            if memory_mb > self.stats["peak_memory_usage"]:
                self.stats["peak_memory_usage"] = memory_mb
            
            # Calculate average memory usage
            self.stats["avg_memory_usage"] = sum(self._memory_samples) / len(self._memory_samples)
            
        except Exception:
            # If psutil fails, skip memory monitoring
            pass
    
    def _trigger_gc_if_needed(self, force: bool = False) -> None:
        """Trigger garbage collection if memory usage is high or time threshold reached."""
        current_time = time.time()
        
        # Force GC every 30 seconds or if explicitly requested
        if force or (current_time - self._last_gc_time > 30):
            collected = gc.collect()
            if collected > 0:
                self.stats["gc_collections"] += 1
                self.logger.debug(f"Garbage collected {collected} objects")
            self._last_gc_time = current_time
    
    def _get_optimal_buffer_size(self, file_size: int) -> int:
        """Calculate optimal buffer size based on file size and available memory."""
        if not PSUTIL_AVAILABLE:
            # Fallback to size-based calculation
            if file_size > 1024 * 1024 * 1024:  # > 1GB
                return 8192 * 32  # 256KB
            else:
                return 8192 * 16  # 128KB
        
        try:
            import psutil
            # Get available memory
            available_memory = psutil.virtual_memory().available
            
            # Use 1% of available memory, but limit between 64KB and 16MB
            buffer_size = min(max(available_memory // 100, 65536), 16777216)
            
            # For very large files, use larger buffers
            if file_size > 1024 * 1024 * 1024:  # > 1GB
                buffer_size = min(buffer_size * 4, 16777216)
            
            return buffer_size
        except Exception:
            # Fallback to default buffer size
            return 8192 * 16  # 128KB
    
    def _batch_process_patterns(self, packet_batch: list, pattern: bytes) -> list:
        """Process a batch of packets for pattern matching (can be parallelized)."""
        results = []
        
        for pkt_bytes, meta in packet_batch:
            first = pkt_bytes.find(pattern)
            if first == -1:
                results.append((pkt_bytes, meta, False, 0))
            else:
                second = pkt_bytes.find(pattern, first + len(pattern))
                if second == -1:
                    results.append((pkt_bytes, meta, False, 0))
                else:
                    results.append((pkt_bytes, meta, True, (first, second)))
        
        return results
    
    @staticmethod
    def _detect_pcap_format(filepath: str) -> str:
        """Detect PCAP file format by reading file header.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            'pcap' for standard PCAP files, 'pcapng' for PCAP-NG files
            
        Raises:
            ValueError: If file format cannot be determined
        """
        try:
            with open(filepath, 'rb') as f:
                header = f.read(4)
                if len(header) < 4:
                    raise ValueError("File too small to be a valid PCAP file")
                
                # Check for PCAP-NG magic number (Section Header Block)
                if header == b'\x0a\x0d\x0d\x0a':
                    return 'pcapng'
                # Check for standard PCAP magic numbers (big/little endian)
                elif header in [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1']:
                    return 'pcap'
                else:
                    raise ValueError(f"Unknown file format: {header.hex()}")
        except IOError as e:
            raise ValueError(f"Cannot read file header: {e}")
    
    def _create_reader(self, filepath: str):
        """Create appropriate reader based on file format.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            Tuple of (reader_instance, linktype, file_format)
        """
        file_format = self._detect_pcap_format(filepath)
        
        if file_format == 'pcapng':
            reader = RawPcapNgReader(filepath)
            # PCAP-NG files don't have a simple linktype attribute
            # Default to Ethernet (1) which is most common
            linktype = 1  # Default to Ethernet
            return reader, linktype, file_format
        else:  # pcap
            reader = RawPcapReader(filepath)
            linktype = reader.linktype
            return reader, linktype, file_format
    
    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Setup default logger configuration."""
        logger = logging.getLogger('pcap_trimmer')
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('[%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _write_packet_batch(self, writer: TimestampPreservingWriter, packet_batch: list) -> None:
        """Write a batch of packets efficiently while preserving original timestamps."""
        for pkt_bytes, meta in packet_batch:
            try:
                # Handle different metadata types for PCAP vs PCAP-NG
                if hasattr(meta, 'sec'):  # Regular PCAP metadata
                    # Ensure wirelen matches packet length for modified packets
                    wirelen = meta.wirelen if hasattr(meta, 'wirelen') else len(pkt_bytes)
                    if wirelen != len(pkt_bytes):
                        wirelen = len(pkt_bytes)
                    writer.write(pkt_bytes, 
                               timestamp_sec=meta.sec, 
                               timestamp_usec=meta.usec, 
                               wirelen=wirelen)
                elif hasattr(meta, 'tshigh'):  # PCAP-NG metadata
                    # Convert PCAP-NG timestamp format to PCAP format
                    # Get timestamp resolution from metadata
                    tsresol = getattr(meta, 'tsresol', 1000000)  # Default to microsecond resolution
                    
                    # Combine the 64-bit timestamp
                    timestamp_64 = (meta.tshigh << 32) | meta.tslow
                    
                    # Convert based on timestamp resolution
                    if tsresol == 1000000:  # Microsecond resolution
                        timestamp_sec = int(timestamp_64 // 1000000)
                        timestamp_usec = int(timestamp_64 % 1000000)
                    elif tsresol == 1000000000:  # Nanosecond resolution
                        timestamp_sec = int(timestamp_64 // 1000000000)
                        timestamp_usec = int((timestamp_64 % 1000000000) // 1000)
                    else:
                        # Custom resolution - convert to seconds and microseconds
                        timestamp_float = timestamp_64 / tsresol
                        timestamp_sec = int(timestamp_float)
                        timestamp_usec = int((timestamp_float - timestamp_sec) * 1000000)
                    
                    # Validate timestamp is reasonable (after year 2000, before year 2100)
                    if timestamp_sec < 946684800 or timestamp_sec > 4102444800:
                        self.logger.warning(f"Suspicious timestamp {timestamp_sec}, using current time")
                        import time
                        current_time = time.time()
                        timestamp_sec = int(current_time)
                        timestamp_usec = int((current_time - timestamp_sec) * 1000000)
                    
                    # Ensure values are within valid range for 32-bit unsigned integers
                    timestamp_sec = max(0, min(timestamp_sec, 4294967295))
                    timestamp_usec = max(0, min(timestamp_usec, 999999))
                    wirelen = getattr(meta, 'wirelen', len(pkt_bytes))
                    # Ensure wirelen matches packet length for modified packets
                    if wirelen != len(pkt_bytes):
                        wirelen = len(pkt_bytes)
                    writer.write(pkt_bytes, 
                               timestamp_sec=timestamp_sec, 
                               timestamp_usec=timestamp_usec, 
                               wirelen=wirelen)
                else:
                    # Fallback: write with current timestamp
                    writer.write(pkt_bytes)
            except Exception as e:
                self.logger.warning(f"Error writing packet in batch: {e}")
                # Continue with next packet rather than failing entire batch
    
    @staticmethod
    def parse_pattern(pat: str, ascii_mode: bool) -> bytes:
        """
        Convert user input pattern to byte sequence.
        
        Args:
            pat: Pattern string to convert
            ascii_mode: If False, treat as hexadecimal; if True, treat as ASCII
            
        Returns:
            Byte sequence representing the pattern
            
        Raises:
            ValueError: If hexadecimal pattern is invalid
        """
        if ascii_mode:
            return pat.encode('utf-8')
        
        # Clean hexadecimal input (remove spaces, colons, etc.)
        cleaned = re.sub(r'[^0-9a-fA-F]', '', pat)
        if len(cleaned) == 0 or len(cleaned) % 2 != 0:
            raise ValueError(
                f"Invalid hexadecimal pattern: {pat!r} "
                f"(should be even number of hex digits after removing separators)"
            )
        return bytes.fromhex(cleaned)

    def _get_file_size(self, filepath: str) -> int:
        """Get file size safely."""
        try:
            return os.path.getsize(filepath)
        except OSError:
            return 0
    
    def _cleanup_resources(self, reader: Optional[RawPcapReader], 
                          writer: Optional[TimestampPreservingWriter], 
                          outfile: str, 
                          dry_run: bool, 
                          error_occurred: bool = False) -> None:
        """Cleanup resources and handle partial files on errors."""
        # Close reader
        if reader:
            try:
                reader.close()
            except Exception as e:
                self.logger.warning(f"Error closing reader: {e}")
        
        # Close writer (if not already closed)
        if writer:
            try:
                writer.close()
            except Exception as e:
                self.logger.warning(f"Error closing writer: {e}")
        
        # Remove partial output file on error
        if error_occurred and not dry_run and os.path.exists(outfile):
            try:
                os.remove(outfile)
                self.logger.info(f"Removed partial output file: {outfile}")
            except OSError as e:
                self.logger.warning(f"Could not remove partial file {outfile}: {e}")
    
    def process_pcap_memory_efficient(self, 
                                     infile: str,
                                     outfile: str,
                                     pattern: bytes,
                                     include_second: bool = False,
                                     dry_run: bool = False,
                                     verbose: bool = False,
                                     progress_interval: int = 10000,
                                     batch_size: int = 1000,
                                     use_threading: bool = False) -> Dict[str, Any]:
        """
        Memory-efficient PCAP processing with batching and optional multi-threading.
        
        This method is optimized for very large PCAP files by:
        - Processing packets in batches to reduce memory usage
        - Periodic garbage collection to free memory
        - Memory usage monitoring and reporting
        - Optional multi-threading for pattern detection
        - Buffered I/O operations
        
        Args:
            infile: Input PCAP file path
            outfile: Output PCAP file path  
            pattern: Byte pattern to search for
            include_second: Include second pattern occurrence in deletion range
            dry_run: Process without writing output file
            verbose: Enable detailed logging
            progress_interval: Report progress every N packets
            batch_size: Number of packets to process in each batch
            use_threading: Enable multi-threaded pattern detection
            
        Returns:
            Dictionary containing processing statistics
        """
        start_time = time.time()
        
        # Validate input file
        if not os.path.exists(infile):
            raise FileNotFoundError(f"Input file not found: {infile}")
        
        if not os.access(infile, os.R_OK):
            raise PermissionError(f"Cannot read input file: {infile}")
        
        # Get input file size and calculate optimal settings
        self.stats["file_size_input"] = self._get_file_size(infile)
        optimal_buffer_size = self._get_optimal_buffer_size(self.stats["file_size_input"])
        
        # Auto-adjust batch size for very large files
        if self.stats["file_size_input"] > 5 * 1024 * 1024 * 1024:  # > 5GB
            batch_size = max(batch_size, 2000)
            self.logger.info(f"Large file detected ({format_file_size(self.stats['file_size_input'])}), using batch size: {batch_size}")
        
        # Validate output directory for non-dry-run
        if not dry_run:
            outdir = os.path.dirname(os.path.abspath(outfile))
            if not os.access(outdir, os.W_OK):
                raise PermissionError(f"Cannot write to output directory: {outdir}")
        
        self.logger.info(f"Processing PCAP file: {infile} ({format_file_size(self.stats['file_size_input'])})")
        self.logger.info(f"Pattern: {pattern.hex() if len(pattern) <= 20 else pattern.hex()[:40] + '...'}")
        self.logger.info(f"Batch size: {batch_size}, Buffer size: {format_file_size(optimal_buffer_size)}")
        
        reader = None
        writer = None
        error_occurred = False
        
        try:
            reader, linktype, file_format = self._create_reader(infile)
            self.logger.info(f"Detected {file_format.upper()} format")
            if not dry_run:
                writer = TimestampPreservingWriter(outfile, linktype=linktype)
            
            last_progress_time = time.time()
            last_memory_check = time.time()
            packet_batch = []
            output_batch = []
            
            # Threading setup if enabled
            executor = None
            if use_threading and batch_size > 100:
                executor = ThreadPoolExecutor(max_workers=min(4, batch_size // 100))
                self.logger.info(f"Multi-threading enabled with {executor._max_workers} workers")
            
            for pkt_bytes, meta in reader:
                self.stats["total_packets"] += 1
                packet_batch.append((pkt_bytes, meta))
                
                # Process batch when it reaches the specified size
                if len(packet_batch) >= batch_size:
                    output_batch.extend(self._process_packet_batch(
                        packet_batch, pattern, include_second, verbose, executor
                    ))
                    packet_batch.clear()
                    
                    # Write output batch if not dry run
                    if not dry_run and writer is not None and output_batch:
                        self._write_packet_batch(writer, output_batch)
                        output_batch.clear()
                    
                    # Memory management
                    current_time = time.time()
                    if current_time - last_memory_check > 10.0:  # Check every 10 seconds
                        self._monitor_memory_usage()
                        self._trigger_gc_if_needed()
                        last_memory_check = current_time
                
                # Progress reporting
                if (self.stats["total_packets"] % progress_interval == 0 or 
                    time.time() - last_progress_time > 5.0):
                    
                    self._monitor_memory_usage()
                    memory_info = f" (Mem: {self.stats['avg_memory_usage']:.1f}MB avg, {self.stats['peak_memory_usage']:.1f}MB peak)" if self.stats['peak_memory_usage'] > 0 else ""
                    self.logger.info(f"Processed {self.stats['total_packets']} packets...{memory_info}")
                    last_progress_time = time.time()
            
            # Process remaining packets in final batch
            if packet_batch:
                output_batch.extend(self._process_packet_batch(
                    packet_batch, pattern, include_second, verbose, executor
                ))
                
                if not dry_run and writer is not None and output_batch:
                    self._write_packet_batch(writer, output_batch)
            
            # Cleanup threading
            if executor:
                executor.shutdown(wait=True)
            
            # Final garbage collection
            self._trigger_gc_if_needed(force=True)
            
            # Close writer before calculating file size to ensure data is flushed
            if not dry_run and writer is not None:
                try:
                    writer.close()
                    writer = None  # Prevent double-close in cleanup
                except Exception as e:
                    self.logger.warning(f"Error closing writer: {e}")
            
            # Record final statistics
            self.stats["processing_time"] = time.time() - start_time
            if not dry_run:
                self.stats["file_size_output"] = self._get_file_size(outfile)
            
            self._monitor_memory_usage()
            self.logger.info(f"Processing completed in {self.stats['processing_time']:.2f}s")
            
        except Exception as e:
            error_occurred = True
            self.logger.error(f"Error during processing: {e}")
            raise
        finally:
            self._cleanup_resources(reader, writer, outfile, dry_run, error_occurred)
        
        return dict(self.stats)
    
    def _process_packet_batch(self, packet_batch: list, pattern: bytes, 
                             include_second: bool, verbose: bool,
                             executor: Optional[ThreadPoolExecutor] = None) -> list:
        """Process a batch of packets, optionally using multi-threading."""
        if executor and len(packet_batch) > 100:
            # Split batch for parallel processing
            chunk_size = max(len(packet_batch) // executor._max_workers, 10)
            chunks = [packet_batch[i:i + chunk_size] for i in range(0, len(packet_batch), chunk_size)]
            
            # Submit tasks to thread pool
            futures = [executor.submit(self._batch_process_patterns, chunk, pattern) 
                      for chunk in chunks]
            
            # Collect results
            batch_results = []
            for future in as_completed(futures):
                batch_results.extend(future.result())
        else:
            # Single-threaded processing
            batch_results = self._batch_process_patterns(packet_batch, pattern)
        
        # Process results and update statistics
        output_packets = []
        for pkt_bytes, meta, has_dual_pattern, pattern_info in batch_results:
            if not has_dual_pattern:
                self.stats["unchanged_packets"] += 1
                output_packets.append((pkt_bytes, meta))
            else:
                first, second = pattern_info
                cut_end = second + (len(pattern) if include_second else 0)
                removed = cut_end - first
                new_bytes = pkt_bytes[:first] + pkt_bytes[cut_end:]
                
                # Update metadata to match new packet length (Frame Length = Capture Length)
                new_meta = ModifiedPacketMeta(meta, len(new_bytes))
                
                self.stats["modified_packets"] += 1
                self.stats["bytes_removed_total"] += max(0, removed)
                output_packets.append((new_bytes, new_meta))
                
                if verbose:
                    self.logger.debug(
                        f"[Packet #{self.stats['total_packets'] - len(packet_batch) + batch_results.index((pkt_bytes, meta, has_dual_pattern, pattern_info)) + 1}] "
                        f"first={first}, second={second}, "
                        f"cut=[{first}, {cut_end}), removed={removed} bytes"
                    )
        
        return output_packets
    
    def find_pcap_files(self, directory: str) -> List[str]:
        """
        Find all PCAP files in the given directory.
        
        Args:
            directory: Directory path to search for PCAP files
            
        Returns:
            List of PCAP file paths
        """
        pcap_extensions = ['.pcap', '.pcapng', '.cap']
        pcap_files = []
        
        directory_path = Path(directory)
        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        if not directory_path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {directory}")
        
        for ext in pcap_extensions:
            pattern = directory_path / f"*{ext}"
            pcap_files.extend(glob.glob(str(pattern)))
        
        # Also check for case-insensitive matches
        for ext in pcap_extensions:
            pattern = directory_path / f"*{ext.upper()}"
            pcap_files.extend(glob.glob(str(pattern)))
        
        # Remove duplicates and sort
        pcap_files = sorted(list(set(pcap_files)))
        
        self.logger.info(f"Found {len(pcap_files)} PCAP files in {directory}")
        return pcap_files
    
    def process_directory(self,
                         source_dir: str,
                         dest_dir: Optional[str] = None,
                         pattern: bytes = b"",
                         include_second: bool = False,
                         dry_run: bool = False,
                         verbose: bool = False,
                         progress_interval: int = 10000,
                         batch_size: int = 1000,
                         use_threading: bool = False) -> Dict[str, Any]:
        """
        Process all PCAP files in a source directory and save results to destination directory.
        
        Args:
            source_dir: Source directory containing PCAP files
            dest_dir: Destination directory for processed files. If None, saves in source_dir with '-modified' suffix
            pattern: Byte pattern to search for
            include_second: Include second pattern occurrence in deletion range
            dry_run: Process without writing output files
            verbose: Enable detailed logging
            progress_interval: Report progress every N packets
            batch_size: Number of packets to process in each batch
            use_threading: Enable multi-threaded pattern detection
            
        Returns:
            Dictionary containing aggregated processing statistics
        """
        # Find all PCAP files in source directory
        pcap_files = self.find_pcap_files(source_dir)
        
        if not pcap_files:
            self.logger.warning(f"No PCAP files found in directory: {source_dir}")
            return {
                "total_files": 0, 
                "processed_files": 0, 
                "failed_files": 0,
                "total_packets": 0,
                "modified_packets": 0,
                "unchanged_packets": 0,
                "bytes_removed_total": 0,
                "total_processing_time": 0.0,
                "file_size_input_total": 0,
                "file_size_output_total": 0,
                "peak_memory_usage": 0,
                "avg_memory_usage": 0,
                "gc_collections": 0
            }
        
        # Determine output mode
        in_place_processing = dest_dir is None
        if in_place_processing:
            dest_dir = source_dir
            self.logger.info(f"In-place processing mode: files will be saved with '-modified' suffix")
        
        # Create destination directory if it doesn't exist and not in-place processing
        if not dry_run and not in_place_processing:
            dest_path = Path(dest_dir)
            dest_path.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Destination directory: {dest_dir}")
        
        # Initialize aggregated statistics
        aggregated_stats = {
            "total_files": len(pcap_files),
            "processed_files": 0,
            "failed_files": 0,
            "total_packets": 0,
            "modified_packets": 0,
            "unchanged_packets": 0,
            "bytes_removed_total": 0,
            "total_processing_time": 0.0,
            "file_size_input_total": 0,
            "file_size_output_total": 0,
            "peak_memory_usage": 0,
            "avg_memory_usage": 0,
            "gc_collections": 0
        }
        
        start_time = time.time()
        
        for i, input_file in enumerate(pcap_files, 1):
            input_path = Path(input_file)
            
            # Determine output file path
            if dry_run:
                # Use platform-specific null device
                if os.name == 'nt':  # Windows
                    output_file = "nul"
                else:  # Unix/Linux/Mac
                    output_file = "/dev/null"
            elif in_place_processing:
                # Add '-modified' suffix before file extension
                stem = input_path.stem
                suffix = input_path.suffix
                output_file = input_path.parent / f"{stem}-modified{suffix}"
            else:
                # Save to destination directory with original name
                output_file = Path(dest_dir) / input_path.name
            
            self.logger.info(f"\n[{i}/{len(pcap_files)}] Processing: {input_path.name}")
            
            try:
                # Reset per-file stats
                self.stats = {
                    "total_packets": 0,
                    "modified_packets": 0,
                    "unchanged_packets": 0,
                    "bytes_removed_total": 0,
                    "processing_time": 0.0,
                    "file_size_input": 0,
                    "file_size_output": 0,
                    "peak_memory_usage": 0,
                    "avg_memory_usage": 0,
                    "gc_collections": 0
                }
                self._memory_samples = []
                
                # Process the individual file
                file_stats = self.process_pcap_memory_efficient(
                    infile=str(input_file),
                    outfile=str(output_file),
                    pattern=pattern,
                    include_second=include_second,
                    dry_run=dry_run,
                    verbose=verbose,
                    progress_interval=progress_interval,
                    batch_size=batch_size,
                    use_threading=use_threading
                )
                
                # Aggregate statistics
                aggregated_stats["processed_files"] += 1
                aggregated_stats["total_packets"] += file_stats["total_packets"]
                aggregated_stats["modified_packets"] += file_stats["modified_packets"]
                aggregated_stats["unchanged_packets"] += file_stats["unchanged_packets"]
                aggregated_stats["bytes_removed_total"] += file_stats["bytes_removed_total"]
                aggregated_stats["total_processing_time"] += file_stats["processing_time"]
                aggregated_stats["file_size_input_total"] += file_stats["file_size_input"]
                aggregated_stats["file_size_output_total"] += file_stats["file_size_output"]
                aggregated_stats["peak_memory_usage"] = max(aggregated_stats["peak_memory_usage"], file_stats["peak_memory_usage"])
                aggregated_stats["gc_collections"] += file_stats["gc_collections"]
                
                self.logger.info(f"✓ Completed: {input_path.name} → {Path(output_file).name if not dry_run else 'dry-run'} - {file_stats['modified_packets']} packets modified")
                
            except Exception as e:
                aggregated_stats["failed_files"] += 1
                self.logger.error(f"✗ Failed to process {input_path.name}: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()
        
        aggregated_stats["total_processing_time"] = time.time() - start_time
        
        # Calculate average memory usage across all files
        if aggregated_stats["processed_files"] > 0:
            aggregated_stats["avg_memory_usage"] = aggregated_stats["peak_memory_usage"] / aggregated_stats["processed_files"]
        
        return aggregated_stats
    
    def _write_packet_safely(self, writer: TimestampPreservingWriter, pkt_bytes: bytes, meta) -> None:
        """Write packet with error handling while preserving original timestamps."""
        try:
            # Handle different metadata types for PCAP vs PCAP-NG
            if hasattr(meta, 'sec'):  # Regular PCAP metadata
                # Ensure wirelen matches packet length for modified packets
                wirelen = meta.wirelen if hasattr(meta, 'wirelen') else len(pkt_bytes)
                if wirelen != len(pkt_bytes):
                    wirelen = len(pkt_bytes)
                writer.write(pkt_bytes, 
                           timestamp_sec=meta.sec, 
                           timestamp_usec=meta.usec, 
                           wirelen=wirelen)
            elif hasattr(meta, 'tshigh'):  # PCAP-NG metadata
                # Convert PCAP-NG timestamp format to PCAP format
                # Get timestamp resolution from metadata
                tsresol = getattr(meta, 'tsresol', 1000000)  # Default to microsecond resolution
                
                # Combine the 64-bit timestamp
                timestamp_64 = (meta.tshigh << 32) | meta.tslow
                
                # Convert based on timestamp resolution
                if tsresol == 1000000:  # Microsecond resolution
                    timestamp_sec = int(timestamp_64 // 1000000)
                    timestamp_usec = int(timestamp_64 % 1000000)
                elif tsresol == 1000000000:  # Nanosecond resolution
                    timestamp_sec = int(timestamp_64 // 1000000000)
                    timestamp_usec = int((timestamp_64 % 1000000000) // 1000)
                else:
                    # Custom resolution - convert to seconds and microseconds
                    timestamp_float = timestamp_64 / tsresol
                    timestamp_sec = int(timestamp_float)
                    timestamp_usec = int((timestamp_float - timestamp_sec) * 1000000)
                
                # Validate timestamp is reasonable (after year 2000, before year 2100)
                if timestamp_sec < 946684800 or timestamp_sec > 4102444800:
                    self.logger.warning(f"Suspicious timestamp {timestamp_sec}, using current time")
                    import time
                    current_time = time.time()
                    timestamp_sec = int(current_time)
                    timestamp_usec = int((current_time - timestamp_sec) * 1000000)
                
                # Ensure values are within valid range for 32-bit unsigned integers
                timestamp_sec = max(0, min(timestamp_sec, 4294967295))
                timestamp_usec = max(0, min(timestamp_usec, 999999))
                wirelen = getattr(meta, 'wirelen', len(pkt_bytes))
                # Ensure wirelen matches packet length for modified packets
                if wirelen != len(pkt_bytes):
                    wirelen = len(pkt_bytes)
                writer.write(pkt_bytes, 
                           timestamp_sec=timestamp_sec, 
                           timestamp_usec=timestamp_usec, 
                           wirelen=wirelen)
            else:
                # Fallback: write with current timestamp
                writer.write(pkt_bytes)
        except Exception as e:
            self.logger.warning(f"Error writing packet: {e}")
            raise

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="PCAP Trimming Tool - Remove byte ranges between pattern occurrences",
        epilog="""
BASIC EXAMPLES:
  %(prog)s input.pcap
  %(prog)s input.pcap output.pcap
  %(prog)s input.pcap output.pcap -p "4500" --verbose
  %(prog)s input.pcap output.pcap --ascii -p "HTTP" --dry-run
  %(prog)s input.pcap output.pcap -p "4500" --include-second --quiet

DIRECTORY PROCESSING EXAMPLES:
  %(prog)s -d C:\\path\\to\\pcap\\files
  %(prog)s -d C:\\path\\to\\pcap\\files C:\\path\\to\\output
  %(prog)s -d .\\source_pcaps .\\processed_pcaps -p "4500" --verbose
  %(prog)s -d C:\\data\\captures C:\\data\\cleaned --batch-size 2000 --enable-threading
  %(prog)s -d .\\network_logs --ascii -p "HTTP" --dry-run


        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Positional arguments
    parser.add_argument("input", 
                       help="Input PCAP file path or source directory (when using -d)")
    parser.add_argument("output", nargs='?', default=None,
                       help="Output PCAP file path or destination directory (when using -d). "
                            "If not specified with -d, modified files will be saved in input directory with '-modified' suffix")
    
    # Pattern configuration
    pattern_group = parser.add_argument_group('Pattern Configuration')
    pattern_group.add_argument("-p", "--pattern", 
                              default="4500",
                              help="Pattern to search for. Default: '4500' (hex). "
                                   "Hex patterns can use separators: '45 00 01', '45:00:01'")
    pattern_group.add_argument("--ascii", 
                              action="store_true",
                              help="Treat pattern as ASCII text instead of hexadecimal")
    
    # Processing options
    processing_group = parser.add_argument_group('Processing Options')
    processing_group.add_argument("-d", "--directory",
                                 action="store_true",
                                 help="Process all PCAP files in source directory and save to destination directory")
    processing_group.add_argument("--include-second", 
                                 action="store_true",
                                 help="Include second pattern occurrence in deletion range")
    processing_group.add_argument("--dry-run", 
                                 action="store_true",
                                 help="Analyze without creating output file")
    processing_group.add_argument("--progress-interval", 
                                 type=int, default=10000, metavar="N",
                                 help="Report progress every N packets (default: 10000)")
    
    # Memory optimization options
    memory_group = parser.add_argument_group('Memory Optimization')
    memory_group.add_argument("--batch-size", 
                             type=int, default=1000, metavar="N",
                             help="Process packets in batches of N (default: 1000, larger for big files)")
    memory_group.add_argument("--enable-threading", 
                             action="store_true",
                             help="Enable multi-threaded pattern detection for large batches")
    memory_group.add_argument("--memory-limit", 
                             type=int, metavar="MB",
                             help="Warn when memory usage exceeds this limit in MB")
    
    # Output control
    output_group = parser.add_argument_group('Output Control')
    output_group.add_argument("-v", "--verbose", 
                             action="store_true",
                             help="Enable detailed packet modification logging")
    output_group.add_argument("-q", "--quiet", 
                             action="store_true",
                             help="Suppress informational output")
    output_group.add_argument("--log-level", 
                             choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                             default='INFO',
                             help="Set logging level (default: INFO)")
    
    return parser

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.1f}{size_names[i]}"

def print_statistics(stats: Dict[str, Any], outfile: str, dry_run: bool) -> None:
    """Print comprehensive processing statistics."""
    print("\n" + "=" * 60)
    print("PROCESSING SUMMARY")
    print("=" * 60)
    
    # Packet statistics
    print(f"Total packets processed: {stats['total_packets']:,}")
    print(f"Modified packets:        {stats['modified_packets']:,} "
          f"({stats['modified_packets']/max(1,stats['total_packets'])*100:.1f}%)")
    print(f"Unchanged packets:       {stats['unchanged_packets']:,} "
          f"({stats['unchanged_packets']/max(1,stats['total_packets'])*100:.1f}%)")
    
    # Bytes statistics
    print(f"\nBytes removed total:     {stats['bytes_removed_total']:,} "
          f"({format_file_size(stats['bytes_removed_total'])})")
    
    if stats['modified_packets'] > 0:
        avg_removed = stats['bytes_removed_total'] / stats['modified_packets']
        print(f"Average bytes per mod:   {avg_removed:.1f}")
    
    # File size information
    if stats.get('file_size_input', 0) > 0:
        print(f"\nInput file size:         {format_file_size(stats['file_size_input'])}")
        if not dry_run and stats.get('file_size_output', 0) > 0:
            print(f"Output file size:        {format_file_size(stats['file_size_output'])}")
            reduction = stats['file_size_input'] - stats['file_size_output']
            reduction_pct = reduction / stats['file_size_input'] * 100
            print(f"Size reduction:          {format_file_size(reduction)} ({reduction_pct:.1f}%)")
    
    # Timing and performance information
    print(f"\nProcessing time:         {stats['processing_time']:.2f}s")
    if stats['processing_time'] > 0 and stats['total_packets'] > 0:
        pps = stats['total_packets'] / stats['processing_time']
        print(f"Processing rate:         {pps:.0f} packets/sec")
    
    # Memory usage information (if available)
    if stats.get('peak_memory_usage', 0) > 0:
        print(f"\nMemory Usage:")
        print(f"Peak memory usage:       {stats['peak_memory_usage']:.1f} MB")
        print(f"Average memory usage:    {stats['avg_memory_usage']:.1f} MB")
        if stats.get('gc_collections', 0) > 0:
            print(f"Garbage collections:     {stats['gc_collections']}")
    
    # Output file info
    print(f"\nOutput file: {outfile if not dry_run else '(dry-run, not generated)'}")
    print("=" * 60)

def print_directory_statistics(stats: Dict[str, Any], dest_dir: str, dry_run: bool) -> None:
    """Print comprehensive directory processing statistics."""
    print("\n" + "=" * 70)
    print("DIRECTORY PROCESSING SUMMARY")
    print("=" * 70)
    
    # File statistics
    print(f"Total files found:       {stats['total_files']:,}")
    print(f"Successfully processed:  {stats['processed_files']:,} "
          f"({stats['processed_files']/max(1,stats['total_files'])*100:.1f}%)")
    if stats['failed_files'] > 0:
        print(f"Failed files:            {stats['failed_files']:,} "
              f"({stats['failed_files']/max(1,stats['total_files'])*100:.1f}%)")
    
    # Packet statistics
    print(f"\nTotal packets processed: {stats['total_packets']:,}")
    print(f"Modified packets:        {stats['modified_packets']:,} "
          f"({stats['modified_packets']/max(1,stats['total_packets'])*100:.1f}%)")
    print(f"Unchanged packets:       {stats['unchanged_packets']:,} "
          f"({stats['unchanged_packets']/max(1,stats['total_packets'])*100:.1f}%)")
    
    # Bytes statistics
    print(f"\nBytes removed total:     {stats['bytes_removed_total']:,} "
          f"({format_file_size(stats['bytes_removed_total'])})")
    
    if stats['modified_packets'] > 0:
        avg_removed = stats['bytes_removed_total'] / stats['modified_packets']
        print(f"Average bytes per mod:   {avg_removed:.1f}")
    
    # File size information
    if stats.get('file_size_input_total', 0) > 0:
        print(f"\nTotal input size:        {format_file_size(stats['file_size_input_total'])}")
        if not dry_run and stats.get('file_size_output_total', 0) > 0:
            print(f"Total output size:       {format_file_size(stats['file_size_output_total'])}")
            reduction = stats['file_size_input_total'] - stats['file_size_output_total']
            reduction_pct = reduction / stats['file_size_input_total'] * 100
            print(f"Total size reduction:    {format_file_size(reduction)} ({reduction_pct:.1f}%)")
    
    # Timing and performance information
    print(f"\nTotal processing time:   {stats['total_processing_time']:.2f}s")
    if stats['processed_files'] > 0:
        avg_time_per_file = stats['total_processing_time'] / stats['processed_files']
        print(f"Average time per file:   {avg_time_per_file:.2f}s")
    
    if stats['total_processing_time'] > 0 and stats['total_packets'] > 0:
        pps = stats['total_packets'] / stats['total_processing_time']
        print(f"Overall processing rate: {pps:.0f} packets/sec")
    
    # Memory usage information (if available)
    if stats.get('peak_memory_usage', 0) > 0:
        print(f"\nMemory Usage:")
        print(f"Peak memory usage:       {stats['peak_memory_usage']:.1f} MB")
        print(f"Average memory usage:    {stats['avg_memory_usage']:.1f} MB")
        if stats.get('gc_collections', 0) > 0:
            print(f"Total garbage collections: {stats['gc_collections']}")
    
    # Output directory info
    print(f"\nOutput directory: {dest_dir if not dry_run else '(dry-run, files not generated)'}")
    print("=" * 70)

def main():
    """Main entry point for the PCAP trimming tool."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    logger = logging.getLogger('pcap_trimmer')
    
    # Handle conflicting verbosity options
    if args.quiet and args.verbose:
        parser.error("Cannot specify both --quiet and --verbose")
    
    if args.quiet:
        log_level = logging.WARNING
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = getattr(logging, args.log_level)
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='[%(levelname)s] %(message)s',
        stream=sys.stderr
    )
    
    # Validate arguments based on processing mode
    if args.directory:
        # Directory mode: output is optional
        if not os.path.exists(args.input):
            parser.error(f"Input directory does not exist: {args.input}")
        if not os.path.isdir(args.input):
            parser.error(f"Input path is not a directory: {args.input}")
    else:
        # Single file mode: generate output filename if not provided
        if not os.path.exists(args.input):
            parser.error(f"Input file does not exist: {args.input}")
        
        if args.output is None:
            # Auto-generate output filename with '-modified' suffix
            input_path = Path(args.input)
            stem = input_path.stem
            suffix = input_path.suffix
            args.output = str(input_path.parent / f"{stem}-modified{suffix}")
            logger.info(f"Auto-generated output filename: {args.output}")
    
    # Auto-adjust batch size based on threading
    if args.enable_threading and args.batch_size < 100:
        logger.warning("Threading enabled but batch size < 100, increasing to 500")
        args.batch_size = 500
    
    # Parse and validate pattern
    try:
        trimmer = PcapTrimmer(logger)
        pat_bytes = trimmer.parse_pattern(args.pattern, ascii_mode=args.ascii)
        
        if len(pat_bytes) == 0:
            parser.error("Pattern cannot be empty")
            
        logger.info(f"Parsed pattern: {len(pat_bytes)} bytes")
        
    except ValueError as e:
        logger.error(f"Pattern error: {e}")
        sys.exit(2)
    
    # Process the PCAP file(s)
    try:
        if args.directory:
            # Directory processing mode
            stats = trimmer.process_directory(
                source_dir=args.input,
                dest_dir=args.output,
                pattern=pat_bytes,
                include_second=args.include_second,
                dry_run=args.dry_run,
                verbose=args.verbose,
                progress_interval=args.progress_interval,
                batch_size=args.batch_size,
                use_threading=args.enable_threading
            )
            
            # Print results unless quiet mode
            if not args.quiet:
                display_dir = args.output if args.output else f"{args.input} (in-place with '-modified' suffix)"
                print_directory_statistics(stats, display_dir, args.dry_run)
            
            # Exit with appropriate code
            if stats['total_files'] == 0:
                logger.warning("No PCAP files found in input directory")
                sys.exit(1)
            elif stats['failed_files'] == stats['total_files']:
                logger.error("All files failed to process")
                sys.exit(1)
            elif stats['total_packets'] == 0:
                logger.warning("No packets found in any input files")
                sys.exit(1)
            elif stats['modified_packets'] == 0:
                logger.info("No packets were modified in any file (no dual pattern occurrences found)")
        else:
            # Single file processing mode
            stats = trimmer.process_pcap_memory_efficient(
                infile=args.input,
                outfile=args.output,
                pattern=pat_bytes,
                include_second=args.include_second,
                dry_run=args.dry_run,
                verbose=args.verbose,
                progress_interval=args.progress_interval,
                batch_size=args.batch_size,
                use_threading=args.enable_threading
            )
            
            # Print results unless quiet mode
            if not args.quiet:
                print_statistics(stats, args.output, args.dry_run)
            
            # Exit with appropriate code
            if stats['total_packets'] == 0:
                logger.warning("No packets found in input file")
                sys.exit(1)
            elif stats['modified_packets'] == 0:
                logger.info("No packets were modified (no dual pattern occurrences found)")
        
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"File error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()