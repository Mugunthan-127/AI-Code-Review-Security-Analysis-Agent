import os
import urllib.request
import base64
import zlib
from fpdf import FPDF
from fpdf.enums import XPos, YPos

class PDF(FPDF):
    def header(self):
        # Draw a subtle top line
        self.set_line_width(0.5)
        self.set_draw_color(14, 165, 233) # Cyan-like brand color
        self.line(10, 10, 200, 10)
        
        # Main Title
        self.set_font('helvetica', 'B', 18)
        self.set_text_color(20, 20, 20)
        self.cell(0, 12, 'AI Code Review & Security Analysis Agent', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        
        # Subtitle
        self.set_font('helvetica', 'I', 14)
        self.set_text_color(80, 80, 80)
        self.cell(0, 8, 'Milestone 1 Completion Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(4)
        
        # Author details
        self.set_font('helvetica', 'B', 11)
        self.set_text_color(40, 40, 40)
        self.cell(0, 6, "Prepared by: MUGUNTHAN M", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.set_font('helvetica', 'I', 11)
        self.set_text_color(14, 165, 233)
        self.cell(0, 6, "mugunthanmuthuraman9@gmail.com", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C', link="mailto:mugunthanmuthuraman9@gmail.com")
        self.set_text_color(0, 0, 0)
        self.ln(8)
        
        # Bottom header line
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(8)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font('helvetica', 'I', 9)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()}', new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 13)
        self.set_fill_color(240, 248, 255) # AliceBlue light background
        self.set_text_color(0, 0, 0)
        # Add a subtle left border effect by drawing a small filled rect
        self.set_fill_color(14, 165, 233)
        self.rect(10, self.get_y() + 2, 2, 6, 'F')
        
        self.set_x(14)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        self.ln(2)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 7, body)
        self.ln(6)

def create_report():
    pdf = PDF()
    pdf.add_page()
    
    repo_link = "https://github.com/Mugunthan-127/AI-Code-Review-Security-Analysis-Agent"
    
    pdf.chapter_title("1. Project Overview")
    overview = (
        "The AI Code Review & Security Analysis Agent is a robust, AI-powered tool designed for deep code analysis, "
        "real-time feedback, and security vulnerability detection. Milestone 1 successfully establishes the foundational "
        "architecture, the Retrieval-Augmented Generation (RAG) pipeline, syntax validation services, and a professional, "
        "interactive client interface."
    )
    pdf.chapter_body(overview)
    
    pdf.chapter_title("2. Completed Modules for Milestone 1")
    
    modules = (
        "2.1 Client Interface (Frontend)\n"
        "- Developed a responsive Single Page Application using React and Vite.\n"
        "- Integrated Monaco Editor for a VS Code-like coding experience (Python & Java support).\n"
        "- Implemented a premium, state-of-the-art Dark Mode UI featuring glassmorphism and micro-animations.\n"
        "- Built interactive components for Security Advice Cards and collapsible Error Snippets.\n\n"
        
        "2.2 Code Submission & Validation Module (FastAPI Backend)\n"
        "- Built RESTful API endpoints for code submission (via direct paste or file upload).\n"
        "- Integrated Python 'ast' and Java 'javalang' libraries for strict syntax and structural validation.\n"
        "- Configured a PostgreSQL database using SQLAlchemy to persist scan history and results.\n\n"
        
        "2.3 Security Analysis & RAG Pipeline\n"
        "- Set up the PostgreSQL vector database utilizing the 'pgvector' extension.\n"
        "- Created ingestion scripts to process and chunk Markdown-based knowledge base files (e.g., OWASP, Secure Coding).\n"
        "- Integrated HuggingFace's 'all-MiniLM-L6-v2' model to generate embeddings for semantic search.\n"
        "- Developed retrieval logic to fetch relevant security context based on validated code submissions.\n\n"
        
        "2.4 Infrastructure & Containerization\n"
        "- Created Docker and Docker Compose configurations to orchestrate the FastAPI backend and PostgreSQL database.\n"
        "- Ensured seamless local development setup and environment consistency."
    )
    pdf.chapter_body(modules)
    
    # Move to next page for architecture diagram to ensure clean layout
    pdf.add_page()
    pdf.chapter_title("3. System Architecture Diagram")
    pdf.set_font('helvetica', '', 11)
    pdf.cell(0, 8, "The following diagram outlines the high-level architecture of the system:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    mermaid_code = """
graph TD
    subgraph Client
        UI[User Interface]
    end

    subgraph Code Submission Module
        API[FastAPI Backend]
        API --> V[Validation Service - ast, javalang]
        V --> DB[(PostgreSQL)]
    end

    subgraph RAG Pipeline Module
        Ingest[Ingestion Script]
        Ingest --> Chunk[Chunker]
        Chunk --> Embed[Embedding Model]
        Embed --> PG[(pgvector)]
        Retrieve[Retrieve Function]
        PG --> Retrieve
    end

    UI --> API
    Retrieve -.-> A1[Code Analysis Agent]
    Retrieve -.-> A2[Security Vulnerability Agent]
    Retrieve -.-> A5[Conversational Code Assistant]
    """
    
    try:
        encoded = base64.urlsafe_b64encode(zlib.compress(mermaid_code.encode('utf-8'), 9)).decode('utf-8')
        img_url = f"https://kroki.io/mermaid/png/{encoded}"
        img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture.png")
        
        req = urllib.request.Request(img_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(img_path, 'wb') as out_file:
            out_file.write(response.read())
        
        pdf.image(img_path, w=160, keep_aspect_ratio=True)
        pdf.ln(10)
    except Exception as e:
        pdf.set_text_color(255, 0, 0)
        pdf.cell(0, 8, f"Failed to load architecture diagram: {e}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
    
    pdf.chapter_title("4. Source Code Repository")
    pdf.set_font('helvetica', '', 11)
    pdf.cell(0, 8, "The complete source code and documentation for Milestone 1 are available at:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_text_color(14, 165, 233)
    pdf.set_font('helvetica', 'U', 11)
    pdf.cell(0, 8, repo_link, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L', link=repo_link)
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)
    
    pdf.chapter_title("5. Next Steps (Milestone 2+ Roadmap)")
    roadmap = (
        "- Remediation Agent: Automatic generation of code fixes and security patches.\n"
        "- Conversational Assistant: Interactive chat to seamlessly explain vulnerabilities.\n"
        "- PR Summary Agent: Automated generation of pull request review summaries for CI/CD integration."
    )
    pdf.chapter_body(roadmap)

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Milestone1_Completion_Report.pdf")
    pdf.output(output_path)
    print(f"Report successfully generated at: {output_path}")

if __name__ == "__main__":
    create_report()
