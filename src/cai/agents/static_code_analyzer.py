"""Static Code Analysis Agent"""
import os
from dotenv import load_dotenv
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.exec_code import execute_code
from cai.tools.others.scripting import scripting_tool

load_dotenv()

# Create system prompt
static_code_analysis_prompt = load_prompt_template("prompts/static_code_analysis_agent.md")

# Define tools for code analysis (following CAI standard pattern)
tools = [
    generic_linux_command,    # For running security tools like semgrep, kingfisher
    execute_code,            # For creating and running analysis scripts
    scripting_tool,          # For inline Python analysis
]

# Create the agent
static_code_analysis_agent = Agent(
    name="Static Code Analyzer",
    description="""Agent specialized in white-box security testing and source code analysis.
                   Expert in finding logic flaws and security vulnerabilities.""",
    instructions=create_system_prompt_renderer(static_code_analysis_prompt),
    tools=tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias0"),
        openai_client=AsyncOpenAI(),
    ),
)

# Transfer function for handoffs
def transfer_to_source_code_analysis_agent(**kwargs):  # pylint: disable=W0613
    """Transfer to static code analysis agent.
    Accepts any keyword arguments but ignores them."""
    return static_code_analysis_agent