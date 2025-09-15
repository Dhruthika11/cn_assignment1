import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def csv_to_pdf(csv_path, pdf_path, title):
    """
    Reads data from a CSV file and converts it into a formatted PDF table.
    """
    try:
        # 1. Read the CSV file using pandas
        df = pd.read_csv(csv_path)
        
        # 2. Set up the PDF document
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # 3. Add a title to the PDF
        title_style = styles['Title']
        title_text = Paragraph(title, title_style)
        elements.append(title_text)
        elements.append(Spacer(1, 24)) # Add space after the title

        # 4. Convert the pandas DataFrame to a list of lists for the table
        # Include the header row
        table_data = [df.columns.tolist()] + df.values.tolist()

        # 5. Create and style the table
        pdf_table = Table(table_data)
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F81BD")), # Header background color
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),          # Header text color
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),                     # Center align all cells
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),             # Header font
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),                    # Header padding
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#D0D8E8")), # Body background color
            ('GRID', (0, 0), (-1, -1), 1, colors.black)                # Add grid lines
        ])
        pdf_table.setStyle(table_style)

        # 6. Add the table to our list of elements and build the PDF
        elements.append(pdf_table)
        doc.build(elements)
        
        print(f"Successfully converted '{csv_path}' to '{pdf_path}'")

    except FileNotFoundError:
        print(f"Error: The file '{csv_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# --- Main execution ---
if __name__ == '__main__':
    csv_file = 'Q1_report_csv.csv'
    pdf_file = 'Q1_report.pdf'
    report_title = 'DNS Queries'
    csv_to_pdf(csv_file, pdf_file, report_title)