import gradio as gr
from transformers import BertTokenizer, BertForSequenceClassification
import torch
import os
from google import genai
import re
import dns.resolver
import requests

# Load phishing detection model
MODEL_NAME = "Danuli/neuro-mail_ai"
token = os.environ.get("HF_TOKEN")

tokenizer = BertTokenizer.from_pretrained(MODEL_NAME, token=token)
model = BertForSequenceClassification.from_pretrained(MODEL_NAME, token=token)
model.eval()

# Phishing detection function
def predict(email_text):
    inputs = tokenizer(
        email_text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    )
    with torch.no_grad():
        outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)[0]
    legit_score = probs[0].item()
    phish_score = probs[1].item()

    label = "🚨 PHISHING" if phish_score > 0.5 else "✅ LEGITIMATE"

    return {
        "Prediction": label,
        "Phishing confidence": f"{phish_score:.1%}",
        "Legitimate confidence": f"{legit_score:.1%}"
    }

# Email generation function
def generate_email(topic, tone):
    api_key = os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)
    prompt = f"Write a {tone.lower()} email about the following topic: {topic}. Include a subject line at the top."
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )
    return response.text

#Email verification function
def validate_email(email):
    # Step 1: format check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return {
            "Format": "❌ Invalid email format",
            "Domain": "—",
            "Mail Server": "—",
            "Verdict": "❌ NOT VALID"
        }
    
    # Step 2: domain MX record check
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mail_server = str(mx_records[0].exchange)
        return {
            "Format": "✅ Valid format",
            "Domain": domain,
            "Mail Server": mail_server,
            "Verdict": "✅ LOOKS REAL"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "Format": "✅ Valid format",
            "Domain": domain,
            "Mail Server": "—",
            "Verdict": "❌ Domain does not exist"
        }
    except dns.resolver.NoAnswer:
        return {
            "Format": "✅ Valid format",
            "Domain": domain,
            "Mail Server": "—",
            "Verdict": "⚠️ Domain exists but no mail server found"
        }
    except Exception as e:
        return {
            "Format": "✅ Valid format",
            "Domain": domain,
            "Mail Server": "—",
            "Verdict": f"⚠️ Could not verify: {str(e)}"
        }


#URL suggestion
def scan_url(url):
    # make sure url has http/https
    if not url.startswith("http"):
        url = "https://" + url

    api_key = os.environ.get("SAFE_BROWSING_API_KEY")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {
            "clientId": "neuro-mail-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        result = response.json()

        if "matches" in result:
            threats = [m["threatType"] for m in result["matches"]]
            return {
                "URL": url,
                "Status": "🚨 DANGEROUS",
                "Threats found": threats,
                "Verdict": "Do NOT visit this URL!"
            }
        else:
            return {
                "URL": url,
                "Status": "✅ SAFE",
                "Threats found": "None detected",
                "Verdict": "URL appears safe according to Google Safe Browsing"
            }
    except Exception as e:
        return {
            "URL": url,
            "Status": "⚠️ Could not scan",
            "Threats found": "—",
            "Verdict": str(e)
        }
    
# Build the UI
with gr.Blocks(css="""
    @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&display=swap');

    body, .gradio-container {
        background-color: #07090f !important;
        font-family: 'DM Sans', sans-serif !important;
        color: #f0f2f8 !important;
    }
    .gr-panel, .gr-box, .gr-form, .gr-block, .wrap {
        background-color: #0e1117 !important;
        border: 1px solid #1e2530 !important;
        border-radius: 12px !important;
    }
    input, textarea, select {
        background-color: #07090f !important;
        color: #f0f2f8 !important;
        border: 1px solid #1e2530 !important;
        border-radius: 8px !important;
        font-family: 'DM Sans', sans-serif !important;
    }
    input:focus, textarea:focus {
        border-color: #4f8ef7 !important;
        outline: none !important;
    }
    label, .gr-label, span {
        color: #8892a4 !important;
        font-family: 'DM Sans', sans-serif !important;
    }
    button.primary {
        background: linear-gradient(135deg, #4f8ef7, #7c5ce8) !important;
        border: none !important;
        border-radius: 8px !important;
        color: #fff !important;
        font-family: 'Syne', sans-serif !important;
        font-weight: 700 !important;
        letter-spacing: 0.03em !important;
    }
    button.secondary {
        background: transparent !important;
        border: 1px solid #1e2530 !important;
        border-radius: 8px !important;
        color: #f0f2f8 !important;
    }
    button.secondary:hover {
        border-color: #4f8ef7 !important;
    }
    .tabs button {
        color: #8892a4 !important;
        font-family: 'DM Sans', sans-serif !important;
        background: transparent !important;
        border: none !important;
    }
    .tabs button.selected {
        color: #4f8ef7 !important;
        border-bottom: 2px solid #4f8ef7 !important;
    }
    .gr-markdown h1, .gr-markdown h2, .gr-markdown h3 {
        font-family: 'Syne', sans-serif !important;
        color: #f0f2f8 !important;
    }
    footer { display: none !important; }
""") as demo:
    gr.HTML("""
        <canvas id="beams-canvas" style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none;filter:blur(15px);"></canvas>
        
        <script>
        (function() {
            const canvas = document.getElementById('beams-canvas');
            const ctx = canvas.getContext('2d');
            let beams = [];
            const TOTAL_BEAMS = 30;

            function resize() {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }

            function createBeam(index) {
                const spacing = canvas.width / 3;
                const column = index % 3;
                return {
                    x: column * spacing + spacing / 2 + (Math.random() - 0.5) * spacing * 0.5,
                    y: canvas.height + Math.random() * canvas.height,
                    width: 80 + Math.random() * 80,
                    length: canvas.height * 2.5,
                    angle: -35 + Math.random() * 10,
                    speed: 0.5 + Math.random() * 0.8,
                    opacity: 0.15 + Math.random() * 0.15,
                    hue: 190 + (index * 70) / TOTAL_BEAMS,
                    pulse: Math.random() * Math.PI * 2,
                    pulseSpeed: 0.02 + Math.random() * 0.03
                };
            }

            function init() {
                resize();
                beams = Array.from({length: TOTAL_BEAMS}, (_, i) => createBeam(i));
            }

            function drawBeam(beam) {
                ctx.save();
                ctx.translate(beam.x, beam.y);
                ctx.rotate(beam.angle * Math.PI / 180);
                const pulsingOpacity = beam.opacity * (0.8 + Math.sin(beam.pulse) * 0.2);
                const grad = ctx.createLinearGradient(0, 0, 0, beam.length);
                grad.addColorStop(0, `hsla(${beam.hue},85%,65%,0)`);
                grad.addColorStop(0.1, `hsla(${beam.hue},85%,65%,${pulsingOpacity * 0.5})`);
                grad.addColorStop(0.4, `hsla(${beam.hue},85%,65%,${pulsingOpacity})`);
                grad.addColorStop(0.6, `hsla(${beam.hue},85%,65%,${pulsingOpacity})`);
                grad.addColorStop(0.9, `hsla(${beam.hue},85%,65%,${pulsingOpacity * 0.5})`);
                grad.addColorStop(1, `hsla(${beam.hue},85%,65%,0)`);
                ctx.fillStyle = grad;
                ctx.fillRect(-beam.width / 2, 0, beam.width, beam.length);
                ctx.restore();
            }

            function animate() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                beams.forEach((beam, i) => {
                    beam.y -= beam.speed;
                    beam.pulse += beam.pulseSpeed;
                    if (beam.y + beam.length < -100) {
                        beams[i] = createBeam(i);
                        beams[i].y = canvas.height + 100;
                    }
                    drawBeam(beam);
                });
                requestAnimationFrame(animate);
            }

            window.addEventListener('resize', resize);
            init();
            animate();
        })();
        </script>

        <div style='text-align:center; padding: 2rem 0 1rem; position:relative; z-index:1;'>
            <div style='display:inline-flex; align-items:center; gap:0.4rem; margin-bottom:0.5rem;'>
                <span style='font-size:2rem; line-height:1;'>📧</span>
                <span style='font-family: Syne, sans-serif; font-weight: 800; font-size: 2rem;
                    color: #f5f0e8; letter-spacing: -0.02em;'>
                    Neuro-Mail AI
                </span>
            </div>
            <p style='color: #a89e8a; font-family: DM Sans, sans-serif; font-size: 0.95rem;'>
                Your smart email assistant — detect phishing, validate emails, scan URLs and generate emails.
            </p>
        </div>
    """)
    gr.Markdown("# 📧 Neuro-Mail AI")
    gr.Markdown("Your smart email assistant — detect phishing, validate emails, scan URLs and generate emails.")

    with gr.Tabs():
        # Tab 1: Phishing Detector
        with gr.Tab("🔍 Phishing Detector"):
            gr.Markdown("### Paste an email below to check if it's phishing or legitimate.")
            with gr.Row():
                with gr.Column():
                    email_input = gr.Textbox(
                        lines=10,
                        placeholder="Paste your email text here...",
                        label="Email Content"
                    )
                    detect_btn = gr.Button("🔍 Analyze Email", variant="primary")
                with gr.Column():
                    detect_output = gr.JSON(label="Result")
            detect_btn.click(fn=predict, inputs=email_input, outputs=detect_output)

        # Tab 2: Email Generator
        with gr.Tab("✍️ Email Generator"):
            gr.Markdown("### Enter a topic and tone to generate a full email.")
            with gr.Row():
                with gr.Column():
                    topic_input = gr.Textbox(
                        lines=3,
                        placeholder="e.g. Meeting reschedule for Monday, Project update to client...",
                        label="Email Topic"
                    )
                    tone_input = gr.Dropdown(
                        choices=["Professional", "Friendly", "Formal", "Casual", "Urgent"],
                        value="Professional",
                        label="Tone"
                    )
                    generate_btn = gr.Button("✍️ Generate Email", variant="primary")
                with gr.Column():
                    email_output = gr.Textbox(
                        lines=15,
                        label="Generated Email"
                        
                    )
            generate_btn.click(fn=generate_email, inputs=[topic_input, tone_input], outputs=email_output)

        # Tab 3: Email Validator
        with gr.Tab("✅ Email Validator"):
            gr.Markdown("### Enter an email address to check if it's valid and real.")
            with gr.Row():
                with gr.Column():
                    email_addr_input = gr.Textbox(
                        lines=1,
                        placeholder="e.g. someone@gmail.com",
                        label="Email Address"
                    )
                    validate_btn = gr.Button("✅ Validate Email", variant="primary")
                with gr.Column():
                    validate_output = gr.JSON(label="Validation Result")
            validate_btn.click(fn=validate_email, inputs=email_addr_input, outputs=validate_output)

        # Tab 4: URL Scanner
        with gr.Tab("🔗 URL Scanner"):
            gr.Markdown("### Paste a URL to check if it's safe or malicious.")
            with gr.Row():
                with gr.Column():
                    url_input = gr.Textbox(
                        lines=1,
                        placeholder="e.g. https://suspicious-site.com",
                        label="URL to scan"
                    )
                    scan_btn = gr.Button("🔗 Scan URL", variant="primary")
                with gr.Column():
                    scan_output = gr.JSON(label="Scan Result")
            scan_btn.click(fn=scan_url, inputs=url_input, outputs=scan_output)
        
demo.launch()
