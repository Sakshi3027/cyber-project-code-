from fpdf import FPDF


def generate_pdf_report(normal_count, anomaly_count, graph_image_path):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font('Arial', 'B', 20)
    pdf.cell(0, 10, 'Anomaly Detection Report', ln=True, align='C')

    pdf.ln(10)

    # Summary Stats
    pdf.set_font('Arial', '', 14)
    pdf.cell(0, 10, f'Total Packets Analyzed: {normal_count + anomaly_count}', ln=True)
    pdf.cell(0, 10, f'Normal Packets: {normal_count}', ln=True)
    pdf.cell(0, 10, f'Anomaly Packets: {anomaly_count}', ln=True)

    pdf.ln(10)

    # Insert the anomaly chart
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Anomaly Timeline Chart:', ln=True)

    pdf.image(graph_image_path, x=10, y=None, w=190)  # adjust width to fit page

    # Save PDF
    pdf.output('Anomaly_Report.pdf')
    print("✅ PDF Report generated successfully: 'Anomaly_Report.pdf'")
