import subprocess
import requests
import os
import sys
import logging
import json
from pathlib import Path
from requests.exceptions import RequestException
from typing import List, Optional, Dict, Any
import coverage

# Set up logging
logging.basicConfig(
 level=logging.INFO,
 format='%(asctime)s - %(levelname)s - %(message)s'
)

class TestGenerator:
 def __init__(self):
     self.api_key = os.getenv('OPENAI_API_KEY')
     self.model = os.getenv('OPENAI_MODEL', 'o1-preview')
     
     try:
         self.max_tokens = int(os.getenv('OPENAI_MAX_TOKENS', '2000'))
     except ValueError:
         logging.error("Invalid value for OPENAI_MAX_TOKENS. Using default value: 2000")
         self.max_tokens = 2000

     if not self.api_key:
         raise ValueError("OPENAI_API_KEY environment variable is not set")

 def get_changed_files(self) -> List[str]:
     """Retrieve list of changed files passed as command-line arguments."""
     if len(sys.argv) <= 1:
         return []
     return [f.strip() for f in sys.argv[1].split() if f.strip()]

 def detect_language(self, file_name: str) -> str:
     """Detect programming language based on file extension."""
     extensions = {
         '.py': 'Python',
         '.js': 'JavaScript',
         '.ts': 'TypeScript',
         '.java': 'Java',
         '.cpp':'C++',
         '.cs': 'C#',
         '.go':'Go'
     }
     _, ext = os.path.splitext(file_name)
     return extensions.get(ext.lower(), 'Unknown')

 def get_test_framework(self, language: str) -> str:
     """Get the appropriate test framework based on language."""
     frameworks = {
         'Python': 'pytest',
         'JavaScript': 'jest',
         'TypeScript': 'jest',
         'Java': 'JUnit',
         'C++': 'Google Test',
         'C#': 'NUnit',
         'Go':'testing'
     }
     return frameworks.get(language, 'unknown')
 
 def get_related_files(self, language: str, file_name: str) -> List[str]:
    """Identify related files based on import statements or includes."""
    related_files = []
    file_directory = Path(file_name).parent  # Get the directory of the current file for relative paths

    try:
        if language in {"Python", "JavaScript", "TypeScript"}:
            with open(file_name, 'r') as f:
                for line in f:
                    if 'import ' in line or 'from ' in line or 'require(' in line:
                        parts = line.split()
                        
                        # Detects relative imports like `from .file_name import ...`
                        if 'from' in parts:
                            index = parts.index('from')
                            module_path = parts[index + 1]
                            if module_path.startswith("."):  # Handles relative import
                                relative_path = module_path.replace(".", "").replace("_", "").replace(".", "/")
                                for ext in ('.py', '.js', '.ts'):
                                    potential_file = file_directory / f"{relative_path}{ext}"
                                    if potential_file.exists():
                                        related_files.append(str(potential_file))
                                        break
                        
                        for part in parts:
                            # Check for relative imports with single dot, without `from`
                            if len(part) > 1 and part[0] == "." and part[1] != ".":
                                path = part.replace(".", "").replace("_", "").replace(".", "/")
                                for ext in ('.py', '.js', '.ts'):
                                    potential_file = file_directory / f"{path}{ext}"
                                    if potential_file.exists():
                                        related_files.append(str(potential_file))
                                        break
                            elif '.' in part:
                                path = part.replace(".", "/")
                                for ext in ('.py', '.js', '.ts'):
                                    potential_file = f"{path}{ext}"
                                    if Path(potential_file).exists():
                                        related_files.append(str(potential_file))
                                        break
                            else:
                                if part.endswith(('.py', '.js', '.ts')) and Path(part).exists():
                                    related_files.append(part)
                                elif part.isidentifier():  # Valid class/module names
                                    base_name = part.lower()
                                    for ext in ('.py', '.js', '.ts'):
                                        potential_file = f"{base_name}{ext}"
                                        if Path(potential_file).exists():
                                            related_files.append(potential_file)
                                            break
                        
        elif language == 'C++':
            return []  # Placeholder for C++ support
        elif language == 'C#':
            return []  # Placeholder for C# support

    except Exception as e:
        logging.error(f"Error identifying related files in {file_name}: {e}")

    return related_files

 def get_related_test_files(self, language: str, file_name: str) -> List[str]:
    """Identify the first related test file based on import statements or includes."""
    related_test_files = []  # Store paths of related test files
    target_file = Path(file_name)  # Convert file_name to a Path object here

    try:
        if language == "Python":
            # Define the directory to search in
            directory = Path(os.path.dirname(os.path.abspath(__file__)))
            logging.debug(f"Searching for related test files in directory: {directory}")

            # Common test file naming patterns
            test_patterns = ["tests.py", "test.py", "test_*.py", "*_test.py"]
            test_files = [file for pattern in test_patterns for file in directory.rglob(pattern)]
            logging.debug(f"Test files found with patterns {test_patterns}: {[str(f) for f in test_files]}")

            # Iterate through each test file to check for potential imports or related identifiers
            for test_file in test_files:
                try:
                    with open(test_file, 'r') as f:
                        for line in f:
                            if 'import' in line or 'from ' in line:
                                # Break down the line into parts to check against the target file name
                                parts = line.split()
                                for part in parts:
                                    normalized_part = part.replace(".", "/") if "." in part else part

                                    # Check if part might represent a path or filename related to `target_file`
                                    for ext in ('.py', '.js', '.ts'):
                                        potential_file = Path(f"{normalized_part}{ext}")
                                        if target_file.exists() and str(target_file) in str(potential_file):
                                            logging.info(f"Related test file found: {test_file}")
                                            related_test_files.append(str(test_file))
                                            break  # Exit loop upon finding the first related file
                        if related_test_files:  # Limit to first match
                            break
                except Exception as e:
                    logging.error(f"Error reading test file {test_file}: {e}")

        # Limit to the first related test file (if any)
        limited_test_files = related_test_files[:1]

    except Exception as e:
        logging.error(f"Error identifying related test files for {file_name}: {e}")
        limited_test_files = []

    return limited_test_files
 
 def generate_coverage_beforehand(self, test_file_path: Path, changed_file: str, language: str):
    """Generate line coverage for the changed file before test generation."""
    if language.lower() != 'python':
        logging.info(f"Coverage analysis is not implemented for language {language}.")
        return None

    cov = coverage.Coverage()
    cov.start()

    # Run the existing test file if it exists
    if test_file_path.exists():
        try:
            # Execute the test file within the current context
            exec(open(test_file_path).read(), globals())
        except Exception as e:
            logging.error(f"Error running tests in {test_file_path}: {e}")
    else:
        logging.info(f"No pre-existing test file found for {changed_file}")

    cov.stop()
    cov.save()

    # Get the line coverage data for the changed file
    uncovered_lines = []
    try:
        file_coverage = cov.analysis2(changed_file)
        _, executed_lines, missing_lines, _ = file_coverage
        uncovered_lines = missing_lines
        logging.info(f"Uncovered lines for {changed_file}: {uncovered_lines}")
    except Exception as e:
        logging.error(f"Error analyzing coverage for {changed_file}: {e}")

    # Return uncovered lines for inclusion in the prompt
    return uncovered_lines
       
       
 
 def generate_coverage_report(self, file_name:str, test_file: Path, language: str):
       """Generate a code coverage report and save it as a text file."""
       report_file = test_file.parent / f"{test_file.stem}_coverage_report.txt"
       if language == "Python":
          # Get the full path of the base file and replace slashes with dots
          current_path = str(os.path.dirname(os.path.abspath(__file__)))  + "/"
          base_name = Path(file_name).resolve()

          base_name = str(base_name).replace(current_path,'').replace('/', '.')
          
          base_name = base_name.replace(file_name,"").replace(".py","") #if (base_name) should still have .
          if (base_name==""):
              base_name="."
       else:
          # For other languages, the base_name remains the stem of the file
          base_name = Path(file_name).stem

       try:
           # Run tests with coverage based on language
           if language == "Python":
               subprocess.run(
                   ["pytest", str(test_file), "--cov="+str(base_name), "--cov-report=term-missing"],
                   stdout=open(report_file, "a"),
                   check=True
               )
           elif language == "JavaScript":
               # Example for JavaScript - replace with the specific coverage tool and command
               subprocess.run(
                   ["jest", "--coverage", "--config=path/to/jest.config.js"],
                   stdout=open(report_file, "a"),
                   check=True
               )
           # Add additional commands for other languages here

           logging.info(f"Code coverage report saved to {report_file}")

       except subprocess.CalledProcessError as e:
           logging.error(f"Error generating coverage report for {test_file}: {e}")

 def ensure_coverage_installed(self, language: str):
       """
       Ensures that the appropriate coverage tool for the given programming language is installed.
       Logs messages for each step.
       """
       try:
           if language.lower() == 'python':
               # Check if 'coverage' is installed for Python
               
               subprocess.check_call([sys.executable, '-m','pip','install', 'pytest-cov'])
               logging.info(f"Coverage tool for Python is already installed.")
           elif language.lower() == 'javascript':
               # Check if 'jest' coverage is available for JavaScript
               subprocess.check_call(['npm', 'list', 'jest'])
               logging.info(f"Coverage tool for JavaScript (jest) is already installed.")
           elif language.lower() == 'java':
               # Check if 'jacoco' is available for Java (typically part of the build process)
               logging.info("Make sure Jacoco is configured in your Maven/Gradle build.")
               # Optionally you can add a check for specific build tool (Maven/Gradle) commands here
           elif language.lower() == 'ruby':
               # Check if 'simplecov' is installed for Ruby
               subprocess.check_call(['gem', 'list', 'simplecov'])
               logging.info(f"Coverage tool for Ruby (simplecov) is already installed.")
           else:
               logging.warning(f"Coverage tool check is not configured for {language}. Please add it manually.")
               return

       except subprocess.CalledProcessError:
           logging.error(f"Coverage tool for {language} is not installed. Installing...")

           try:
               if language.lower() == 'python':
                   subprocess.check_call([sys.executable, '-m','pip','install', 'pytest-cov'])
                   logging.info(f"Coverage tool for Python has been installed.")
               elif language.lower() == 'javascript':
                   subprocess.check_call(['npm', 'install', 'jest'])
                   logging.info(f"Coverage tool for JavaScript (jest) has been installed.")
               elif language.lower() == 'ruby':
                   subprocess.check_call(['gem', 'install', 'simplecov'])
                   logging.info(f"Coverage tool for Ruby (simplecov) has been installed.")
               else:
                   logging.error(f"Could not install coverage tool for {language} automatically. Please install manually.")
           except subprocess.CalledProcessError:
               logging.error(f"Failed to install the coverage tool for {language}. Please install it manually.")

     

 def create_prompt(self, file_name: str, language: str) -> Optional[str]:
    """Create a language-specific prompt for test generation with accurate module and import names in related content."""
    # Attempt to read the primary file's content
    try:
        with open(file_name, 'r') as f:
            code_content = f.read()
    except Exception as e:
        logging.error(f"Error reading file {file_name}: {e}")
        return None

    # Gather related files and their content
    related_files = self.get_related_files(language, file_name)
    related_content = ""
    if related_files:
        for related_file in related_files:
            try:
                with open(related_file, 'r') as rf:
                    file_content = rf.read()
                    module_path = str(Path(related_file).with_suffix('')).replace('/', '.')
                    import_statement = f"import {module_path}"
                    related_content += f"\n\n// Module: {module_path}\n{import_statement}\n{file_content}"
                    logging.info(f"Included content from related file: {related_file} as module {module_path}")
            except Exception as e:
                logging.error(f"Error reading related file {related_file}: {e}")
    else:
        logging.info(f"No related files found for {file_name}")

    # Gather related test files (using only the first one if there are multiple)
    related_test_files = self.get_related_test_files(language, file_name)
    related_test_content = ""
    if related_test_files:
        first_test_file = related_test_files[0] if related_test_files else None
        if first_test_file:
            try:
                with open(first_test_file, 'r') as rf:
                    file_content = rf.read()
                    related_test_content += f"\n\n// Related test file: {first_test_file}\n{file_content}"
                    logging.info(f"Included content from related test file: {first_test_file}")
            except Exception as e:
                logging.error(f"Error reading related test file {first_test_file}: {e}")
        else:
            logging.info(f"No test files found for {file_name}")
    else:
        logging.info(f"No related test files found for {file_name}")

    # Determine test framework
    framework = self.get_test_framework(language)

    # Generate uncovered lines information
    uncovered_lines = self.generate_coverage_beforehand(first_test_file, file_name, language) if first_test_file else []
    if uncovered_lines:
        uncovered_lines_text = f"Uncovered lines: {uncovered_lines}"
        logging.info(f"Uncovered lines for {file_name}: {uncovered_lines}")
    else:
        uncovered_lines_text = "All lines are covered by existing tests."
        logging.info(f"All lines are covered for {file_name}")

    # Construct the prompt
    prompt = f"""Generate unit tests for the following {language} file: {file_name} using {framework}. 

    Requirements:
    1. Prioritize covering the uncovered lines identified in the coverage report below.
    2. Include edge cases, normal cases, and error cases.
    3. Use mocking where appropriate for external dependencies.
    4. Include setup and teardown if needed.
    5. Add descriptive test names and docstrings.
    6. Follow {framework} best practices.
    7. Ensure high code coverage, focusing primarily on the uncovered lines.
    8. Test both success and failure scenarios.

    Code to test (File: {file_name}):

    {code_content}

    Related context:

    {related_content}

    Related test cases:
    {related_test_content}

    Coverage report:
    {uncovered_lines_text}

    Generate only the test code without any explanations or notes.
    """

    logging.info(f"Created prompt for {file_name} with length {len(prompt)} characters")
    return prompt


 def call_openai_api(self, prompt: str) -> Optional[str]:
    """Call OpenAI API to generate test cases."""
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {self.api_key}'
    }
    
    data = {
        'model': self.model,
        'messages': [
            {
                "role": "user",
                "content": prompt
            }
        ],
        'max_completion_tokens': self.max_tokens
    }

    try:
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=data,
            timeout=60
        )
        response.raise_for_status()
        generated_text = response.json()['choices'][0]['message']['content']
        normalized_text = generated_text.replace('“', '"').replace('”', '"').replace("‘", "'").replace("’", "'")
        if normalized_text.startswith('```'):
            first_newline_index = normalized_text.find('\n', 3)
            if first_newline_index != -1:
                normalized_text = normalized_text[first_newline_index+1:]
            else:
                normalized_text = normalized_text[3:]
            if normalized_text.endswith('```'):
                normalized_text = normalized_text[:-3]
        return normalized_text.strip()
    except RequestException as e:
        logging.error(f"API request failed: {e}, Response: {response.text}")
        return None
     
 def make_test_file(self, file_name: str, language: str) -> Path:
     """Save generated test cases to appropriate directory structure."""
     tests_dir = Path('generated_tests')
     tests_dir.mkdir(exist_ok=True)
     lang_dir = tests_dir / language.lower()
     lang_dir.mkdir(exist_ok=True)
     base_name = Path(file_name).stem
     if not base_name.startswith("test_"):
         base_name = f"test_{base_name}"
     extension = '.js' if language == 'JavaScript' else Path(file_name).suffix
     test_file = lang_dir / f"{base_name}{extension}"

     header = ""
     if language.lower() == 'python':
         logging.info("will write python specific header")
         header = (
               "import sys\n"
               "import os\n"
               "sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), \"../..\")))\n\n"
           )
     elif language.lower() == 'go':
         #add stuff for go
         logging.info("go unwritten code for save_test_cases")
   
     try:
         with open(test_file, 'w', encoding='utf-8') as f:
             f.write(header)
             logging.info("wrote header in test file")
             f.close
     except Exception as e:
         logging.error(f"Error adding header to {test_file}: {e}")
       
     return test_file
 
 def save_tests_created(self, test_file: Path,test_cases:str,language:str):
   
     try:
         with open(test_file, 'a', encoding='utf-8') as f:
             f.write(test_cases)
         logging.info(f"Test cases saved to {test_file}")
     except Exception as e:
         logging.error(f"Error saving test cases to {test_file}: {e}")

     if test_file.exists():
         logging.info(f"File {test_file} exists with size {test_file.stat().st_size} bytes.")
     else:
         logging.error(f"File {test_file} was not created.")
     return test_file

     

 def run(self):
     """Main execution method."""
     changed_files = self.get_changed_files()
     if not changed_files:
         logging.info("No files changed.")
         return

     for file_name in changed_files:
         if (file_name!="generate_tests.py"):
          try:
              language = self.detect_language(file_name)
              if language == 'Unknown':
                  logging.warning(f"Unsupported file type: {file_name}")
                  continue

              logging.info(f"Processing {file_name} ({language})")
              prompt = self.create_prompt(file_name, language)
              
              if prompt:
                  
                  #test_cases = self.call_openai_api(prompt)
                  
                  if test_cases:
                      test_cases = test_cases.replace("“", '"').replace("”", '"')

                      self.ensure_coverage_installed(language)

                      test_file_path = self.make_test_file(file_name,language) 

                      
                      test_file = self.save_tests_created(test_file_path,test_cases, language)
                      self.generate_coverage_report(file_name, test_file, language)
                  else:
                      logging.error(f"Failed to generate test cases for {file_name}")
          except Exception as e:
              logging.error(f"Error processing {file_name}: {e}")

if __name__ == '__main__':
 try:
     generator = TestGenerator()
     generator.run()
 except Exception as e:
     logging.error(f"Fatal error: {e}")
     sys.exit(1)