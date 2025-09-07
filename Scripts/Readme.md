# WiGLE Processors

* Replace `39.094845 --lon -76.7298708` (Baltimore, MD) with your coordinates

| **Function** | **Command** | **Description** |
|--------------|-------------|-----------------|
| **Setup & Configuration** |
| Create sample config | `python wigle_processor.py --create-config my_filters.json` | Creates a sample JSON configuration file with example blocked MACs, SSIDs, and regex patterns |
| **Location-Based Filtering** |
| Keep only local networks | `python wigle_processor.py --here --lat 39.094845 --lon -76.7298708 *.csv` | Shows only networks within ~111m of your coordinates (useful for testing your area size) |
| Remove local networks | `python wigle_processor.py --scrub --not-here --lat 39.094845 --lon -76.7298708 *.csv` | **Most common use**: Filters out networks near your home/work before uploading to WiGLE |
| Custom area size | `python wigle_processor.py --scrub --not-here --lat 39.094845 --lon -76.7298708 --delta 0.002 *.csv` | Larger exclusion area (~222m radius instead of default 111m) |
| Small exclusion zone | `python wigle_processor.py --scrub --not-here --lat 39.094845 --lon -76.7298708 --delta 0.0005 *.csv` | Smaller exclusion area (~55m radius) |
| **Privacy & SSID Filtering** |
| Basic scrubbing | `python wigle_processor.py --scrub --config my_filters.json *.csv` | Removes networks based on your filter config (MACs, SSIDs, patterns) |
| Full privacy scrub | `python wigle_processor.py --scrub --config my_filters.json --not-here --lat 39.094845 --lon -76.7298708 *.csv` | **Recommended**: Combines location and SSID/MAC filtering for maximum privacy |
| Custom output location | `python wigle_processor.py --scrub --config my_filters.json --output-dir ./Clean *.csv` | Saves scrubbed files to `./Clean/` instead of default `./Scrub/` |
| **Security Analysis** |
| Find potential stalkers | `python wigle_processor.py --creeps *.csv` | **Security check**: Shows devices seen at multiple locations (could be following you) |
| Encryption statistics | `python wigle_processor.py --encryption *.csv` | Shows percentage breakdown of open/WEP/WPA networks in your data |
| Combined analysis | `python wigle_processor.py --creeps --encryption *.csv` | Runs both stalker detection and encryption analysis |
| **File Processing** |
| Process single file | `python wigle_processor.py --scrub --config my_filters.json wardriving_001.csv` | Process just one specific CSV file |
| Process with wildcards | `python wigle_processor.py --scrub --config my_filters.json wardrive_*.csv` | Process all files matching pattern |
| Process all CSV files | `python wigle_processor.py --scrub --config my_filters.json` | Automatically finds and processes all *.csv files in current directory |

## Most Common Workflows:

### Privacy-Focused Upload Preparation

1. Create your filter config
`python wigle_processor.py --create-config my_filters.json`

2. Edit my_filters.json to add your networks

3. Scrub files for upload (removes home area + personal networks)
`python wigle_processor.py --scrub --config my_filters.json --not-here --lat 39.094845 --lon -76.7298708 *.csv`

4. Upload files from ./Scrub/ directory to WiGLE.net

### Security Analysis

5. Check if anyone might be tracking you
`python wigle_processor.py --creeps *.csv`

6. See what types of networks you encountered  
`python wigle_processor.py --encryption *.csv`

### Work/Corporate Use

7.  Remove work location and company SSIDs before personal upload
`python wigle_processor.py --scrub --config work_filters.json --not-here --lat 39.12345 --lon -76.54321 --delta 0.005 *.csv`

### Testing & Validation
8. See what's in your local area (before filtering)
`python wigle_processor.py --here --lat 39.094845 --lon -76.7298708 *.csv`

9. Test your filter config
`python wigle_processor.py --scrub --config my_filters.json test_file.csv`

### Distance Reference:
- --delta 0.0005 ≈ 55m radius (small building)
- --delta 0.001 ≈ 111m radius (default - city block)  
- --delta 0.002 ≈ 222m radius (neighborhood)
- --delta 0.005 ≈ 555m radius (large campus/mall)
