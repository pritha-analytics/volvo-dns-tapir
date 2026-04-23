from mcp.server.fastmcp import FastMCP
import os
import glob

# Initialize the MCP server
mcp = FastMCP("VolvoDataTool")
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

@mcp.tool()
def fetch_documents(query: str) -> str:
    """Search across internal data files and return matching content.
    Args:
        query: The search string to look for within the internal data files.
    """
    query = query.lower()
    results = []
    
    if not os.path.exists(DATA_DIR):
        return "Error: Data directory not found."
        
    for filepath in glob.glob(os.path.join(DATA_DIR, '*')):
        if os.path.isfile(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                # If query is 'all', 'all files', or empty, return everything
                words = query.lower().split()
                if not query or query.lower() in ["all", "all files", "everything"] or any(word in content.lower() for word in words):
                    results.append(f"--- File: {os.path.basename(filepath)} ---\n{content}")
                    
    return "\n\n".join(results) if results else "No matches found."

@mcp.tool()
def list_available_files() -> str:
    """Returns a list of all available dataset files that can be queried."""
    if not os.path.exists(DATA_DIR):
        return "Error: Data directory not found."
    files = [f for f in os.listdir(DATA_DIR) if os.path.isfile(os.path.join(DATA_DIR, f))]
    return "Available files:\n- " + "\n- ".join(files)

if __name__ == '__main__':
    # Start the server using SSE transport (HTTP) so Kong AI Gateway can proxy the MCP traffic
    # Default port for FastMCP SSE is typically 8000, we'll use 5000 to match our Kong configuration
    # Note: FastMCP run() takes transport, host, port.
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 5000
    mcp.run(transport='sse')
