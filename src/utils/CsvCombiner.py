import pandas as pd
import glob
from pathlib import Path

def combine_csv_files(directory, pattern="*.csv", output_file="combined_data.csv"):
    """
    Combine multiple CSV files into one
    """
    csv_dir = Path(directory)
    
    # Find all CSV files
    csv_files = list(csv_dir.glob(pattern))
    
    if not csv_files:
        print(f"❌ No CSV files found matching pattern '{pattern}'")
        return None
    
    print(f"🔍 Found {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"   • {f.name}")
    
    # Combine all CSV files
    combined_df = pd.DataFrame()
    total_rows = 0
    
    print(f"\n📊 Combining CSV files...")
    
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            combined_df = pd.concat([combined_df, df], ignore_index=True)
            total_rows += len(df)
            print(f"   • {csv_file.name}: {len(df)} rows")
        except Exception as e:
            print(f"   ⚠️  Error reading {csv_file.name}: {e}")
    
    # Save combined file
    output_path = csv_dir / output_file
    combined_df.to_csv(output_path, index=False)
    
    print(f"\n✅ Combined {len(csv_files)} CSV files")
    print(f"📁 Output: {output_path}")
    print(f"📊 Total rows: {total_rows}")
    print(f"📋 Columns: {list(combined_df.columns)}")
    
    return str(output_path)

# Usage
combined_file = combine_csv_files(
    directory="csv/",
    pattern="*.csv",
    output_file="all_logs_combined.csv"
)
