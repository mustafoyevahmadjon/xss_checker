import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse

class Scanner:
    def __init__(self, url, ignore_links=None):
        if ignore_links is None:
            ignore_links = []
        self.target_url = url
        self.target_links = []
        self.session = requests.Session()
        self.links_to_ignore = ignore_links
        self.xss_test_scripts = [
            "<script>alert('XSS')</script>",
            "\"'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>"
        ]
        print(f"[DEBUG] Scanner initialized with target URL: {url}")
        
    def extract_links_from(self, url):
        print(f"[DEBUG] Extracting links from {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            links = [link.get("href") for link in soup.find_all("a", href=True)]
            print(f"[DEBUG] Found links: {links}")
            return links
        
        except requests.RequestException as e:
            print(f"[!] Error fetching links from {url}: {e}")
            return []
        
    def crawl(self, url=None):
        if url is None:
            url = self.target_url
            
            print(f"[DEBUG] Crawling URL: {url}")
            
            href_links = self.extract_links_from(url)
            for link in href_links:
                link = urljoin(url, link)
                
                print(f"[DEBUG] Processing link: {link}")
                
                if any(keyword in link.lower() for keyword in ["login", "logout", "signout"]):
                    print(f"[DEBUG] Ignoring link: {link}")
                    continue
                
                if "#" in link:
                    link = link.split("#")[0]
                
                if self.target_url in link and link not in self.target_links:
                    self.target_links.append(link)
                    print("[+] Found: " + link)
                    self.crawl(link)
    
    def extract_forms(self, url):
        
        print(f"[DEBUG] Extracting forms from {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")
            
            print(f"[DEBUG] Found forms: {forms}")
            
            return forms
        
        except requests.RequestException as e:
            
            print(f"[!] Error fetching forms from {url}: {e}")
            
            return []
    
    def submit_form(self, form, value, url):
        
        print(f"[DEBUG] Submitting form to {url} with value: {value}")
        
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method", "get").lower()
        
        inputs_list = form.find_all("input")
        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            input_value = input.get("value", value if input_type == "text" else "")
                
            if input_name: 
                post_data[input_name] = input_value
                
        print(f"[DEBUG] Form data: {post_data}")
        
        try:
            if method == "post":
                return self.session.post(post_url, data=post_data, timeout=10)
            return self.session.get(post_url, params=post_data)
        except requests.RequestException as e:
            print(f"[!] Error submitting form to {post_url}: {e}")
            return None
        
    def run_scaner(self):
        print(f"[DEBUG] Running scanner on target links: {self.target_links}")
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " + link)
                for script in self.xss_test_scripts:
                    if self.test_xss_in_form(form, link, script):        
                        print(f"[!] XSS discovered in form on {link} with payload: {script}")
                        print(form)       
                        break
                         
            if "=" in link:
                print("[+] Testing " + link) 
                for script in self.xss_test_scripts:
                    print(f"[DEBUG] Testing XSS payload in link: {script}")
                    if self.test_xss_in_link(link, script):
                            print(f"[!] XSS discovered in URL: {link} with payload: {script}")
                            break
                
    def test_xss_in_link(self, url, script):
        print(f"[DEBUG] Testing XSS in link {url} with payload: {script}")
        url = url.replace("=", "=" + script)
        try:
            response = self.session.get(url)
            is_vulnerable = script in response.content.decode("utf-8", errors="ignore")
            print(f"[DEBUG] XSS vulnerability in link {url}: {is_vulnerable}")
            return is_vulnerable
        
        except requests.RequestException as e:
            print(f"[!] Error testing XSS in link {url}: {e}")
            return False
        
    def test_xss_in_form(self, form, url, script):
        print(f"[DEBUG] Testing XSS in form at {url} with payload: {script}")
        response = self.submit_form(form, script, url)
        if response:
            try:
                is_vulnerable = script in response.content.decode("utf-8", errors="ignore")
                print(f"[DEBUG] XSS vulnerability in form at {url}: {is_vulnerable}")
                return is_vulnerable
            except requests.RequestException as e:
                print(f"[!] Error analyzing response for form at {url}: {e}")
        return False
    
if __name__ == "__main__":
    # argument yoki input
    parser = argparse.ArgumentParser(description="Scanner for XSS vulnerabilities")
    parser.add_argument("target_url", nargs="?", help="The URL to scan. If not provided, it will be asked.")
    args = parser.parse_args()
    
    target_url = args.target_url if args.target_url else input("Enter the target URL: ")
    vuln_scaner = Scanner(target_url)
        
    data_dict = {"username": "admin", "password": "password", "Login": "submit"}
    try:
        vuln_scaner.session.post(urljoin(target_url, "login.php"), data=data_dict)
        print(f"[DEBUG] Logged in with credentials: {data_dict}")
    except requests.RequestException as e:
        print(f"[!] Error logging in: {e}")
   
    vuln_scaner.crawl()
    vuln_scaner.run_scaner()
    