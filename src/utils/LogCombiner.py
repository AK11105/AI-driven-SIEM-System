import os
import glob
import gzip
from pathlib import Path

def combine_messages_files(log_directory, output_file="combined_messages.log"):
    """
    Find all messages files (messages, messages.1, etc.) and combine into one .log file
    """
    log_dir = Path(log_directory)
    
    print(f"🔍 Looking for messages files in {log_dir}")
    
    # Find all messages files (including compressed)
    message_files = []
    
    # Pattern matching for messages files
    patterns = [
        "messages",
        "messages.*",
        "messages.*.gz",
        "messages.*.bz2"
    ]
    
    for pattern in patterns:
        files = list(log_dir.glob(pattern))
        message_files.extend(files)
    
    # Remove duplicates and sort
    message_files = sorted(set(message_files), key=lambda x: x.name)
    
    if not message_files:
        print("❌ No messages files found")
        return None
    
    print(f"Found {len(message_files)} files:")
    for f in message_files:
        print(f"   • {f.name}")
    
    # Combine all files
    output_path = log_dir / output_file
    total_lines = 0
    
    print(f"\n📝 Combining files into {output_file}...")
    
    with open(output_path, 'w', encoding='utf-8') as outfile:
        for msg_file in message_files:
            print(f"   • Processing {msg_file.name}...")
            
            try:
                # Handle compressed files
                if msg_file.suffix == '.gz':
                    with gzip.open(msg_file, 'rt', encoding='utf-8', errors='ignore') as infile:
                        lines = infile.readlines()
                else:
                    with open(msg_file, 'r', encoding='utf-8', errors='ignore') as infile:
                        lines = infile.readlines()
                
                # Write lines to output
                outfile.writelines(lines)
                total_lines += len(lines)
                print(f"     Added {len(lines)} lines")
                
            except Exception as e:
                print(f"     ⚠️  Error reading {msg_file.name}: {e}")
    
    file_size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"\n✅ Combined {len(message_files)} files")
    print(f"📁 Output: {output_path}")
    print(f"📊 Total lines: {total_lines}")
    print(f"💾 File size: {file_size_mb:.1f} MB")
    
    return str(output_path)

# Usage
if __name__ == "__main__":
    # Change this to your log directory
    log_directory = "temp/"  # or wherever your messages files are
    
    combined_file = combine_messages_files(
        log_directory=log_directory,
        output_file="combined_messages_1.log"
    )
    
    if combined_file:
        print(f"\n🎉 Ready to use: {combined_file}")
