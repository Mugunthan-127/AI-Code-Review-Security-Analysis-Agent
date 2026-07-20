import pandas as pd
import json

def get_sheet_structure(filename):
    print(f"\n--- {filename} ---")
    try:
        xls = pd.ExcelFile(filename)
        for sheet_name in xls.sheet_names:
            print(f"Sheet: {sheet_name}")
            df = pd.read_excel(filename, sheet_name=sheet_name)
            print(f"Columns: {list(df.columns)}")
            print(f"Preview (first row):")
            if not df.empty:
                print(df.head(1).to_dict('records'))
            else:
                print("Empty")
    except Exception as e:
        print(f"Error: {e}")

get_sheet_structure("Agile_Template_v0.1.xls")
get_sheet_structure("Defect_Tracker Template_v0.1.xlsx")
get_sheet_structure("Unit_Test_Plan_v0.1.xlsx")
