from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from models import ChatLog  # Assume ChatLog is a model
from extensions import db
import string
import os
from werkzeug.utils import secure_filename
import random  # Added for rephrasing functionality

chatbot_bp = Blueprint('chatbot', __name__)

# Define groups of similar questions mapping to the same answer
QUESTION_GROUPS = {
    ("who created you?", "who developed you?", "who made you?", "who is behind you?"):
        "I am Plato, a part of AIVivid, an AI-powered assistant platform. My creators are Anush Shrestha, Sandesh Baral, Sankalpa Paudel, and Tilak Tilija Pun (Team Leader), who built me to help with cybersecurity and more.",

    ("what is AIVivid?", "tell me about AIVivid", "what does AIVivid do?", "who is AIVivid?"):
        "AIVivid is an AI-powered assistant platform, and Plato is here to help you with cybersecurity queries and more.",

    ("how does threat detection work", "explain how threats are detected", "what’s the process for detecting threats?"):
        "We use machine learning models to analyze device and threat patterns in real-time, identifying potential risks quickly.",

    ("is my data safe", "is my information secure?", "how secure is my data?", "do you safeguard my details?"):
        "Yes, AIVivid ensures your data is protected with encryption and strict access controls.",

    ("what is cyber attack", "what defines a cyber attack?", "can you explain a cyber attack?", "what’s a cyber assault?"):
        "A cyber attack is an unauthorized attempt to breach a system or network to steal data or cause disruption.",

    ("what is phishing?", "how does phishing work?", "can you define phishing?", "what’s a phishing scam?"):
        "Phishing is a scam where attackers pretend to be trustworthy entities to trick you into sharing sensitive information.",

    ("how can I prevent phishing?", "what stops phishing?", "how do I avoid phishing scams?", "tips to prevent phishing?"):
        "Avoid clicking unknown links, enable two-factor authentication, and always verify the sender’s identity.",

    ("what is malware?", "what does malware mean?", "can you explain malware?", "what’s malicious software?"):
        "Malware is harmful software designed to damage, disrupt, or gain unauthorized access to your systems.",

    ("how does malware spread?", "what causes malware to spread?", "how is malicious software distributed?"):
        "Malware spreads through email attachments, infected websites, or removable devices like USB drives.",

    ("what is ransomware?", "how does ransomware work?", "what’s ransomware about?", "define ransomware for me?"):
        "Ransomware is a type of malware that locks your data and demands payment to unlock it.",

    ("how do I recover from ransomware?", "what’s the recovery process for ransomware?", "how to fix a ransomware attack?"):
        "Restore data from backups, avoid paying ransoms, and seek help from cybersecurity experts.",

    ("what is a firewall?", "how does a firewall function?", "what’s the purpose of a firewall?", "define firewall?"):
        "A firewall is a security tool that monitors and filters network traffic to block unauthorized access.",

    ("how does a firewall work?", "what’s the mechanism of a firewall?", "explain how firewalls operate?"):
        "It uses predefined rules to allow or block traffic, protecting your network from threats.",

    ("what is encryption?", "how does encryption work?", "what’s the definition of encryption?", "explain data encryption?"):
        "Encryption transforms your data into a secure code, making it unreadable to unauthorized users.",

    ("why is encryption important?", "what’s the value of encryption?", "why should I use encryption?", "benefits of encryption?"):
        "It keeps your sensitive data safe during transfer and storage, preventing interception.",

    ("what is a VPN?", "how does a VPN function?", "what’s a virtual private network?", "define VPN?"):
        "A VPN, or Virtual Private Network, creates a secure, encrypted connection over the internet.",

    ("how does a VPN help?", "what are the benefits of a VPN?", "why use a VPN?", "how does a VPN protect me?"):
        "It hides your IP address and secures your online activity, especially on public networks.",

    ("what is a DDoS attack?", "what’s a distributed denial-of-service attack?", "explain a DDoS?", "define DDoS?"):
        "A DDoS attack overwhelms a server with traffic to make it unavailable to users.",

    ("how do I mitigate DDoS attacks", "what stops a DDoS", "how to protect against DDoS?", "DDoS prevention tips?"):
        "Use traffic filtering, rate limiting, and cloud-based protection services to reduce impact.",

    ("what is two-factor authentication?", "what’s 2FA?", "how does two-factor authentication work?", "define 2FA?"):
        "Two-factor authentication adds a second verification step, like a code from your phone, for extra security.",

    ("why use two-factor authentication?", "what’s the benefit of 2FA?", "why is 2FA important?", "advantages of 2FA?"):
        "It secures your accounts even if your password is stolen.",

    ("what is a zero-day exploit?", "what’s a zero-day vulnerability?", "explain zero-day attacks?", "define zero-day?"):
        "A zero-day exploit targets a flaw unknown to software makers before a patch is available.",

    ("how do I protect against zero-day attacks?", "what prevents zero-day exploits?", "zero-day defense tips?"):
        "Keep software updated and use advanced intrusion detection systems.",

    ("what is a penetration test?", "what’s a pentest?", "how does penetration testing work?", "define penetration testing?"):
        "A penetration test is a simulated attack to uncover weaknesses in your system.",

    ("who conducts penetration tests?", "who performs pentesting?", "who are penetration testers?", "pentest professionals?"):
        "Certified ethical hackers or security experts carry out penetration tests.",

    ("what is social engineering?", "how does social engineering work?", "what’s social engineering about?", "define social engineering?"):
        "Social engineering tricks people into revealing confidential information through manipulation.",

    ("how do I avoid social engineering?", "what prevents social engineering?", "how to stay safe from social engineering?"):
        "Be cautious of unsolicited requests and verify identities before sharing information.",

    ("what is a botnet?", "what’s a botnet network?", "explain botnets?", "define botnet?"):
        "A botnet is a group of hacked devices controlled by an attacker for malicious purposes.",

    ("how are botnets used?", "what do botnets do?", "botnet purposes?", "uses of botnets?"):
        "They’re used for DDoS attacks, sending spam, or mining cryptocurrency.",

    ("what is a password manager", "what does a password manager do?", "explain password managers?", "define password manager?"):
        "A password manager securely stores and creates strong passwords for you.",

    ("why use a password manager", "what’s the benefit of a password manager?", "advantages of password managers?"):
        "It reduces the risk of weak or repeated passwords being hacked.",

    ("what is a data breach?", "what’s a data breach about?", "explain a data breach?", "define data breach?"):
        "A data breach is when unauthorized individuals access your confidential information.",

    ("how do I respond to a data breach?", "what to do after a data breach?", "data breach recovery steps?"):
        "Notify affected parties, investigate the cause, and enhance security measures.",

    ("what is endpoint security?", "what’s endpoint protection?", "explain endpoint security?", "define endpoint security?"):
        "Endpoint security safeguards devices like laptops and phones from cyber threats.",

    ("how does endpoint security work?", "what’s the process of endpoint security?", "explain endpoint protection?"):
        "It uses software to monitor and block threats on connected devices.",

    ("what is a security audit?", "what’s a security review?", "explain security audits?", "define security audit?"):
        "A security audit checks an organization’s defenses and policies for weaknesses.",

    ("why conduct security audits?", "what’s the purpose of a security audit?", "benefits of audits?", "why audit security?"):
        "It helps find vulnerabilities and ensures compliance with security standards.",

    ("what is a man-in-the-middle attack?", "what’s a MITM attack?", "explain MITM?", "define man-in-the-middle?"):
        "A man-in-the-middle attack intercepts communication between you and another party.",

    ("how do I prevent MITM attacks?", "what stops man-in-the-middle attacks?", "MITM prevention tips?"):
        "Use HTTPS, VPNs, and encrypted connections to block interception.",

    ("what is a brute force attack?", "what’s a brute force method?", "explain brute force?", "define brute force?"):
        "A brute force attack tries countless password combinations to break into an account.",

    ("how do I stop brute force attacks?", "what prevents brute force?", "brute force protection tips?"):
        "Use account lockouts and enforce strong, unique passwords.",

    ("what is a trojan horse?", "what’s a trojan?", "explain trojans?", "define trojan horse?"):
        "A trojan horse is malware disguised as harmless software to infiltrate your system.",

    ("how do I detect trojans?", "what finds trojan horses?", "trojan detection methods?", "how to spot trojans?"):
        "Run antivirus scans and avoid downloads from untrusted sources.",

    ("what is a worm?", "what’s a computer worm?", "explain worms?", "define worm?"):
        "A worm is a self-spreading malware that moves across networks without user action.",

    ("how do I remove worms?", "what removes computer worms?", "worm cleanup steps?", "how to eliminate worms?"):
        "Use updated antivirus tools and isolate affected devices.",

    ("what is spyware?", "what’s spyware about?", "explain spyware?", "define spyware?"):
        "Spyware is software that secretly tracks and collects your personal data.",

    ("how do I remove spyware?", "what gets rid of spyware?", "spyware removal tips?", "how to clear spyware?"):
        "Use anti-spyware software and steer clear of suspicious downloads.",

    ("what is a rootkit?", "what’s a rootkit malware?", "explain rootkits?", "define rootkit?"):
        "A rootkit is malware that hides deep in a system to gain admin control.",

    ("how do I detect rootkits?", "what finds rootkit malware?", "rootkit detection tips?", "how to identify rootkits?"):
        "Use specialized tools and monitor for unusual system behavior.",

    ("what is a backdoor?", "what’s a backdoor access?", "explain backdoors?", "define backdoor?"):
        "A backdoor is a hidden entry point that lets attackers bypass security.",

    ("how do I close backdoors?", "what blocks backdoor access?", "backdoor prevention methods?", "how to secure backdoors?"):
        "Patch software and monitor network traffic for suspicious activity.",

    ("what is a honeypot?", "what’s a honeypot system?", "explain honeypots?", "define honeypot?"):
        "A honeypot is a decoy setup to lure attackers and study their methods.",

    ("why use honeypots?", "what’s the benefit of honeypots?", "honeypot advantages?", "why deploy a honeypot?"):
        "They provide insights into attack techniques to strengthen defenses.",

    ("what is a security policy?", "what’s a security plan?", "explain security policies?", "define security policy?"):
        "A security policy is a set of rules to protect an organization’s information assets.",

    ("how do I create a security policy?", "what’s the process for a security policy?", "steps to make a security plan?"):
        "Involve your team, assess risks, and establish clear security guidelines.",

    ("what is a vulnerability assessment?", "what’s a vulnerability check?", "explain vulnerability assessments?", "define vulnerability assessment?"):
        "A vulnerability assessment scans systems to find and fix security weaknesses.",

    ("how often should I do assessments?", "what’s the frequency for vulnerability checks?", "when to assess vulnerabilities?"):
        "Conduct them at least yearly or after major system updates.",

    ("what is patch management?", "what’s patching software?", "explain patch management?", "define patch management?"):
        "Patch management updates software to fix known security holes.",

    ("why is patch management important?", "what’s the value of patching?", "benefits of patch management?", "why update software?"):
        "It stops attackers from exploiting outdated vulnerabilities.",

    ("what is SIEM?", "what’s security information and event management?", "explain SIEM?", "define SIEM?"):
        "SIEM is a system that collects and analyzes security data for real-time monitoring.",

    ("how does SIEM help?", "what are SIEM benefits?", "why use SIEM?", "SIEM advantages?"):
        "It detects threats quickly and helps respond to incidents effectively.",

    ("what is a DoS attack?", "what’s a denial-of-service attack?", "explain DoS?", "define DoS?"):
        "A DoS attack floods a system to make it unavailable to legitimate users.",

    ("how do I defend against DoS?", "what stops DoS attacks?", "DoS protection tips?", "how to block DoS?"):
        "Use rate limiting and traffic analysis tools to mitigate attacks.",

    ("what is SQL injection?", "what’s an SQL attack?", "explain SQL injection?", "define SQL injection?"):
        "SQL injection inserts harmful code into database queries to manipulate data.",

    ("how do I prevent SQL injection?", "what stops SQL attacks?", "SQL injection protection?", "how to block SQL injection?"):
        "Use parameterized queries and validate all user inputs.",

    ("what is XSS?", "what’s cross-site scripting?", "explain XSS?", "define cross-site scripting?"):
        "XSS injects malicious scripts into web pages to affect users.",

    ("how do I prevent XSS?", "what stops cross-site scripting?", "XSS protection tips?", "how to block XSS?"):
        "Sanitize inputs and implement content security policies.",

    ("what is a CA?", "what’s a certificate authority?", "explain CA?", "define certificate authority?"):
        "A CA issues digital certificates to verify the identity of websites.",

    ("why are CAs important?", "what’s the role of certificate authorities?", "CA benefits?", "why use a CA?"):
        "They enable secure, encrypted connections like HTTPS.",

    ("what is PKI?", "what’s public key infrastructure?", "explain PKI?", "define PKI?"):
        "PKI manages digital certificates and encryption keys for secure communication.",

    ("how does PKI work?", "what’s the process of PKI?", "explain PKI functionality?", "how PKI operates?"):
        "It uses public and private key pairs to encrypt and verify data.",

    ("what is SSL?", "what’s secure socket layer?", "explain SSL?", "define SSL?"):
        "SSL is an older protocol that encrypted internet connections.",

    ("what replaced SSL?", "what came after SSL?", "SSL successor?", "what’s the SSL replacement?"):
        "SSL was succeeded by the more secure Transport Layer Security (TLS).",

    ("what is a hash function?", "what’s a hashing algorithm?", "explain hash functions?", "define hash?"):
        "A hash function turns data into a fixed code to check its integrity.",

    ("why use hash functions?", "what’s the purpose of hashing?", "hash function benefits?", "why use hashes?"):
        "They verify data hasn’t changed and secure passwords.",

    ("what is a digital signature?", "what’s a digital sign?", "explain digital signatures?", "define digital signature?"):
        "A digital signature confirms a document’s authenticity using encryption.",

    ("how do I create a digital signature?", "what’s the process for digital signatures?", "how to make a digital sign?"):
        "Sign with your private key and verify with a public key.",

    ("what is threat intelligence?", "what’s cyber threat intelligence?", "explain threat intel?", "define threat intelligence?"):
        "Threat intelligence provides insights into potential cyber threats.",

    ("how do I use threat intelligence?", "what’s threat intel used for?", "threat intelligence applications?", "how to apply threat data?"):
        "Incorporate it into security tools for proactive threat defense.",

    ("what is a SOC?", "what’s a security operations center?", "explain SOC?", "define SOC?"):
        "A SOC is a team that monitors and responds to security threats 24/7.",

    ("why have a SOC?", "what’s the benefit of a SOC?", "SOC advantages?", "why use a security operations center?"):
        "It ensures constant protection and rapid incident response.",

    ("what is zero trust?", "what’s the zero trust model?", "explain zero trust security?", "define zero trust?"):
        "Zero trust is a security approach that trusts no one by default.",

    ("how do I implement zero trust?", "what’s the zero trust setup?", "zero trust deployment steps?", "how to use zero trust?"):
        "Verify all users and devices with strict access controls.",

    ("what is a sandbox?", "what’s a sandbox environment?", "explain sandboxes?", "define sandbox?"):
        "A sandbox is an isolated space to test potentially harmful code safely.",

    ("why use a sandbox?", "what’s the benefit of a sandbox?", "sandbox purposes?", "why deploy a sandbox?"):
        "It prevents malicious code from damaging your main system.",

    ("what is log management?", "what’s managing logs?", "explain log management?", "define log management?"):
        "Log management collects and analyzes system logs for security insights.",

    ("how does log management help?", "what’s the value of log management?", "log management benefits?", "why use log management?"):
        "It helps detect security issues and meet compliance requirements.",

    ("what is a keylogger?", "what’s a keystroke logger?", "explain keyloggers?", "define keylogger?"):
        "A keylogger records your keystrokes to steal sensitive information.",

    ("how do I detect keyloggers?", "what finds keyloggers?", "keylogger detection tips?", "how to spot a keylogger?"):
        "Use antivirus software and watch for unusual device behavior.",

    ("what is privilege escalation?", "what’s escalating privileges?", "explain privilege escalation?", "define privilege escalation?"):
        "Privilege escalation is when an attacker gains higher system access.",

    ("how do I prevent privilege escalation?", "what stops privilege escalation?", "privilege escalation protection?", "how to block privilege escalation?"):
        "Limit user permissions and monitor for suspicious activity.",

    ("what is network security?", "what’s securing a network?", "explain network security?", "define network security?"):
        "Network security protects your network from unauthorized access and threats.",

    ("how do I enhance network security?", "what improves network safety?", "network security tips?", "how to strengthen network security?"):
        "Use firewalls, VPNs, and intrusion detection systems.",

    ("what is an IDS?", "what’s an intrusion detection system?", "explain IDS?", "define IDS?"):
        "An IDS monitors network traffic to spot suspicious activities.",

    ("how does IDS differ from IPS?", "what’s the difference between IDS and IPS?", "IDS vs IPS explained?", "IDS and IPS comparison?"):
        "IDS detects threats, while IPS actively blocks them.",

    ("what is application security?", "what’s securing applications?", "explain app security?", "define application security?"):
        "Application security protects software from cyber threats during development.",

    ("how do I ensure application security?", "what secures apps?", "application security practices?", "how to protect applications?"):
        "Review code and follow secure development guidelines.",

    ("what is cloud security?", "what’s securing the cloud?", "explain cloud protection?", "define cloud security?"):
        "Cloud security safeguards data and apps hosted in cloud environments.",

    ("how do I secure cloud data?", "what protects cloud information?", "cloud security methods?", "how to safeguard cloud data?"):
        "Encrypt data and manage user access with strict controls.",

    ("what is a security token?", "what’s a security key?", "explain security tokens?", "define security token?"):
        "A security token is a device or code used to verify your identity.",

    ("why use security tokens?", "what’s the benefit of tokens?", "security token advantages?", "why use a security key?"):
        "They add an extra layer of protection to your accounts.",

    ("what is biometric authentication?", "what’s biometric security?", "explain biometrics?", "define biometric authentication?"):
        "Biometric authentication uses unique traits like fingerprints for access.",

    ("how does biometric authentication work?", "what’s the biometric process?", "explain biometric login?", "how biometrics function?"):
        "It scans your trait and matches it to a stored template.",

    ("what are biometric authentication types?", "what kinds of biometrics exist?", "biometric methods?", "types of biometric security?"):
        "Common types include fingerprints, facial recognition, and iris scans.",
}

# Flatten groups into a single dictionary
RESPONSES = {}
for questions, answer in QUESTION_GROUPS.items():
    for q in questions:
        RESPONSES[q] = answer

# Add your existing predefined responses here
RESPONSES.update({
    "is my data safe?": "Yes, AIVivid ensures your data is protected with encryption and strict access controls.",
    "what is a cyber attack?": "A cyber attack is an unauthorized attempt to breach a system or network to steal data or cause disruption.",
    "hi": "Hello! How can I assist you today?",
    "hello": "Hello! How can I assist you today?",
    "good morning": "Good morning! How may I help you?",
    "good afternoon": "Good afternoon! What can I do for you?",
    "good evening": "Good evening! How can I support you?",
    "how are you?": "I'm doing well, thank you! How about you?",
    "thank you": "You're welcome! I'm glad to help.",
    "phishing": "Phishing is a scam where attackers pretend to be trustworthy entities to trick you into sharing sensitive information.",
    "ransomware": "Ransomware is a type of malware that locks your data and demands payment to unlock it.",
    "malware": "Malware is harmful software designed to damage, disrupt, or gain unauthorized access to your systems.",
})

# Enhanced synonym dictionary for rephrasing
SYNONYMS = {
    "safe": ["secure", "protected", "safeguarded"],
    "data": ["information", "records", "details"],
    "attack": ["assault", "breach", "strike"],
    "protect": ["defend", "guard", "shield"],
    "prevent": ["stop", "avoid", "block"],
    "explain": ["describe", "clarify", "elaborate"],
    "important": ["crucial", "essential", "vital"],
    "use": ["utilize", "employ", "apply"],
    "system": ["network", "platform", "infrastructure"],
    "malware": ["virus", "malicious software", "threat"],
    "hello": ["hi", "greetings", "hey"],
    "assist": ["help", "support", "aid"],
    "today": ["now", "this day", "currently"],
}

# Predefined rephrases for single words or short greetings
PREDEFINED_REPHRASES = {
    "hello": ["Greetings! How can I support you?", "Hi there! What can I do for you?"],
    "hi": ["Hello! How may I assist you?", "Hey! What can I help with?"],
}

def rephrase_text(text):
    """Rephrase text with improved logic for single words and sentence structure."""
    text = text.strip()
    words = text.split()

    # Handle single-word inputs or greetings
    if len(words) <= 1 and text.lower() in PREDEFINED_REPHRASES:
        return random.choice(PREDEFINED_REPHRASES[text.lower()])

    # Detect and handle greetings followed by questions
    if text.lower().startswith(("hello", "hi")) and "?" in text:
        greeting_part, question_part = text.split("?", 1)
        greeting_rephrased = random.choice(PREDEFINED_REPHRASES.get(greeting_part.lower().split()[0], [greeting_part]))
        question_rephrased = rephrase_text(question_part.strip() + "?")  # Recursively rephrase the question part
        return f"{greeting_rephrased} {question_rephrased}"

    # Rephrase multi-word sentences
    rephrased_words = []
    is_question = text.endswith("?")
    for word in words:
        clean_word = word.lower().strip(string.punctuation)
        if clean_word in SYNONYMS and random.random() > 0.3:  # 70% chance to replace
            synonym = random.choice(SYNONYMS[clean_word])
            if word.islower():
                rephrased_words.append(synonym)
            elif word.istitle():
                rephrased_words.append(synonym.capitalize())
            else:
                rephrased_words.append(synonym.upper())
        else:
            rephrased_words.append(word)

    rephrased_text = " ".join(rephrased_words)

    # Apply context-aware restructuring with "I am sorry" for questions
    if is_question and not rephrased_text.startswith("I am sorry"):
        return f"I am not sure, {rephrased_text.lower()[:-1]}?"
    elif not is_question and not rephrased_text.startswith("Let me"):
        return f"{rephrased_text.lower()}."
    return rephrased_text

def normalize_message(msg):
    """Lowercase and remove punctuation for normalized matching."""
    msg = msg.lower().strip()
    msg = msg.translate(str.maketrans('', '', string.punctuation))
    return msg

def find_answer(message):
    """Find answer by exact or keyword matching."""
    normalized = normalize_message(message)

    # Exact match
    if normalized in RESPONSES:
        return RESPONSES[normalized]

    # Keyword-based match for single words or partial inputs
    keywords = {
        "phishing": RESPONSES.get("what is phishing?", ""),
        "ransomware": RESPONSES.get("what is ransomware?", ""),
        "malware": RESPONSES.get("what is malware?", ""),
        "firewall": RESPONSES.get("what is a firewall?", ""),
        "encryption": RESPONSES.get("what is encryption?", ""),
        "vpn": RESPONSES.get("what is a VPN?", ""),
        "ddos": RESPONSES.get("what is a DDoS attack?", ""),
        "2fa": RESPONSES.get("what is two-factor authentication?", ""),
        "zeroday": RESPONSES.get("what is a zero-day exploit?", ""),
        "pentest": RESPONSES.get("what is a penetration test?", ""),
        "socialengineering": RESPONSES.get("what is social engineering?", ""),
        "botnet": RESPONSES.get("what is a botnet?", ""),
        "passwordmanager": RESPONSES.get("what is a password manager?", ""),
        "databreach": RESPONSES.get("what is a data breach?", ""),
        "endpoint": RESPONSES.get("what is endpoint security?", ""),
        "audit": RESPONSES.get("what is a security audit?", ""),
        "mitm": RESPONSES.get("what is a man-in-the-middle attack?", ""),
        "bruteforce": RESPONSES.get("what is a brute force attack?", ""),
        "trojan": RESPONSES.get("what is a trojan horse?", ""),
        "worm": RESPONSES.get("what is a worm?", ""),
        "spyware": RESPONSES.get("what is spyware?", ""),
        "rootkit": RESPONSES.get("what is a rootkit?", ""),
        "backdoor": RESPONSES.get("what is a backdoor?", ""),
        "honeypot": RESPONSES.get("what is a honeypot?", ""),
        "policy": RESPONSES.get("what is a security policy?", ""),
        "vulnerability": RESPONSES.get("what is a vulnerability assessment?", ""),
        "patch": RESPONSES.get("what is patch management?", ""),
        "siem": RESPONSES.get("what is SIEM?", ""),
        "dos": RESPONSES.get("what is a DoS attack?", ""),
        "sqlinjection": RESPONSES.get("what is SQL injection?", ""),
        "xss": RESPONSES.get("what is XSS?", ""),
        "ca": RESPONSES.get("what is a CA?", ""),
        "pki": RESPONSES.get("what is PKI?", ""),
        "ssl": RESPONSES.get("what is SSL?", ""),
        "hash": RESPONSES.get("what is a hash function?", ""),
        "digitalsignature": RESPONSES.get("what is a digital signature?", ""),
        "threatintel": RESPONSES.get("what is threat intelligence?", ""),
        "soc": RESPONSES.get("what is a SOC?", ""),
        "zerotrust": RESPONSES.get("what is zero trust?", ""),
        "sandbox": RESPONSES.get("what is a sandbox?", ""),
        "logmanagement": RESPONSES.get("what is log management?", ""),
        "keylogger": RESPONSES.get("what is a keylogger?", ""),
        "privilege": RESPONSES.get("what is privilege escalation?", ""),
        "networksecurity": RESPONSES.get("what is network security?", ""),
        "ids": RESPONSES.get("what is an IDS?", ""),
        "application": RESPONSES.get("what is application security?", ""),
        "cloud": RESPONSES.get("what is cloud security?", ""),
        "token": RESPONSES.get("what is a security token?", ""),
        "biometric": RESPONSES.get("what is biometric authentication?", ""),
    }
    for key, value in keywords.items():
        if key in normalized:
            return value

    # Keyword-based fallback
    creator_keywords = ["creator", "developed", "made", "built"]
    if any(word in normalized for word in creator_keywords):
        return QUESTION_GROUPS[("who created you?", "who developed you?", "who made you?", "who is behind you?")]

    aivid_keywords = ["aivid", "what is aivid", "about aivid"]
    if any(word in normalized for word in aivid_keywords):
        return QUESTION_GROUPS[("what is AIVivid?", "tell me about AIVivid", "what does AIVivid do?", "who is AIVivid?")]

    return "Sorry, I didn’t understand that. Can you try rephrasing or asking a question?"

@chatbot_bp.route('/chat')
@login_required
def chat_page():
    return render_template('chatbot.html')

@chatbot_bp.route('/api/chatbot', methods=['POST'])
@login_required
def chatbot():
    data = request.get_json()
    message = data.get('message', '')
    print("Received message:", message)

    reply = find_answer(message)

    try:
        new_log = ChatLog(user_id=current_user.id, message=message, response=reply)
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging to database: {e}")
        return jsonify({'reply': reply}), 500

    return jsonify({'reply': reply})

@chatbot_bp.route('/api/rephrase', methods=['POST'])
@login_required
def rephrase():
    data = request.get_json()
    text = data.get('text', '')
    if not text:
        return jsonify({'rephrased': 'No text provided'}), 400

    rephrased_text = rephrase_text(text)
    return jsonify({'rephrased': rephrased_text})

@chatbot_bp.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(filepath)
        return jsonify({'reply': f"File <strong>{filename}</strong> uploaded successfully."})
    return jsonify({'reply': "No file uploaded."})

@chatbot_bp.route('/api/chatbot/history', methods=['GET'])
@login_required
def get_chat_history():
    logs = ChatLog.query.filter_by(user_id=current_user.id)\
        .order_by(ChatLog.created_at.desc())\
        .limit(10).all()

    return jsonify([
        {'message': log.message, 'response': log.response}
        for log in reversed(logs)  # oldest to newest
    ])

@chatbot_bp.route('/api/chatbot/clear', methods=['POST'])
@login_required
def clear_chat_history():
    try:
        ChatLog.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'message': 'Chat history cleared successfully.'})
    except Exception as e:
        print(f"Error clearing chat history: {e}")
        return jsonify({'message': 'Failed to clear chat history.'}), 500

@chatbot_bp.route('/api/chatbot/delete', methods=['POST'])
@login_required
def delete_chat_history():
    try:
        ChatLog.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'message': 'Chat history deleted successfully.'})
    except Exception as e:
        print(f"Error deleting chat history: {e}")
        return jsonify({'message': 'Failed to delete chat history.'}), 500

@chatbot_bp.route('/api/chatbot/delete-all', methods=['POST'])
@login_required
def delete_all_chat_history():
    try:
        ChatLog.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'message': 'All chat history deleted successfully.'})
    except Exception as e:
        print(f"Error deleting all chat history: {e}")
        return jsonify({'message': 'Failed to delete all chat history.'}), 500

@chatbot_bp.route('/api/photo', methods=['POST'])
@login_required
def take_photo():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join('uploads', filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(filepath)
    return jsonify({'message': f"Photo <strong>{filename}</strong> uploaded successfully."})