document.addEventListener('DOMContentLoaded', () => {
    // --- Ebook Form Logic ---
    const ebookForm = document.getElementById('ebook-form');
    if(ebookForm) {
        ebookForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const emailInput = document.getElementById('ebook-email');
            const successMessage = document.getElementById('ebook-success-message');
            if (emailInput.value && emailInput.checkValidity()) {
                
                // *** FIX: SEND EBOOK LEAD TO HUBSPOT ***
                const ebookLeadData = { 
                    email: emailInput.value,
                    ebook_download_source: 'Decoding Your AI Business Score' 
                };
                sendToHubSpot(ebookLeadData);

                if (successMessage) successMessage.classList.remove('hidden');
                
                const link = document.createElement('a');
                link.href = 'https://raw.githubusercontent.com/ej1906/Pariss-united-website/main/Decoding%20Your%20AI%20Business%20Score%20(1).pdf';
                link.download = 'Decoding-Your-AI-Business-Score.pdf';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);

                emailInput.value = '';
            } else {
                emailInput.classList.add('invalid');
            }
        });
    }

    // --- Main Application Logic ---
    let currentStep = 1;
    const totalSteps = 5; 
    let userData = {};
    let leadScore = 0; 

    const aiRecommendations = {
        'ecommerce': { 'lead_generation': [{ title: "AI-Powered Ad Targeting", description: "Use AI to analyze customer data and create hyper-targeted ad campaigns on social media and Google to attract high-intent shoppers." }, { title: "Predictive Analytics for Trends", description: "Leverage AI to predict emerging product trends, allowing you to stock the right products at the right time." }], 'conversion': [{ title: "Personalized Product Recommendations", description: "Implement an AI engine on your site to show visitors products they are most likely to buy, based on browsing history." }, { title: "AI Chatbots for 24/7 Sales", description: "Deploy a chatbot to answer customer questions, offer discounts, and guide users to checkout, even outside business hours." }], 'efficiency': [{ title: "Automated Inventory Management", description: "Use AI to forecast demand and automate reordering, reducing overstock and stockouts." }, { title: "Dynamic Pricing Optimization", description: "Implement AI tools to adjust prices in real-time based on demand, competitor pricing, and inventory levels to maximize profit." }], 'customer_support': [{ title: "AI Helpdesk for Instant Support", description: "Use an AI-powered helpdesk to instantly resolve common customer queries, freeing up your human agents for complex issues." }, { title: "Sentiment Analysis of Reviews", description: "Analyze customer reviews with AI to understand sentiment and proactively address common complaints." }] },
        'service': { 'lead_generation': [{ title: "AI Lead Scoring", description: "Implement an AI system to score incoming leads based on their likelihood to convert, so your sales team can focus on the hottest prospects." }, { title: "Content Idea Generation", description: "Use AI to analyze industry trends and generate ideas for blog posts, webinars, and lead magnets that attract your target audience." }], 'conversion': [{ title: "Automated Email Follow-ups", description: "Create personalized, AI-driven email sequences to nurture leads and guide them through your sales funnel." }, { title: "AI-Powered Proposal Generation", description: "Use AI tools to quickly generate customized proposals and quotes, shortening your sales cycle." }], 'efficiency': [{ title: "AI Project Management Assistants", description: "Utilize AI to automate task scheduling, resource allocation, and progress tracking for your client projects." }, { title: "Meeting Transcription & Summarization", description: "Automatically transcribe and summarize client meetings with AI, ensuring no detail is missed and saving administrative time." }], 'customer_support': [{ title: "Proactive Client Outreach", description: "Use AI to monitor client activity and sentiment, and trigger proactive check-ins to improve retention." }, { title: "24/7 Appointment Booking Bot", description: "Implement an AI chatbot on your website that can qualify leads and book consultation calls automatically." }] },
        'saas': { 'lead_generation': [{ title: "AI-Enhanced Content Marketing", description: "Use AI to optimize your blog content for SEO and identify topics that will attract high-quality organic traffic." }, { title: "Predictive Lead Scoring for Demos", description: "Analyze user behavior on your site to predict which free trial users are most likely to convert to paid, and prioritize them for sales outreach." }], 'conversion': [{ title: "AI-Powered Onboarding", description: "Create a personalized onboarding experience for new users, with AI-driven tips and tutorials based on their actions in your app." }, { title: "Churn Prediction", description: "Use AI to identify users at risk of churning and trigger automated retention campaigns to keep them as customers." }], 'efficiency': [{ title: "Automated Code Review", description: "Leverage AI tools to review code for bugs and vulnerabilities, speeding up your development cycle." }, { title: "AI-Driven Product Roadmapping", description: "Analyze user feedback and feature requests with AI to prioritize your product roadmap and build what customers truly want." }], 'customer_support': [{ title: "AI-Powered Knowledge Base", description: "Create a smart, searchable knowledge base that provides users with instant answers to their questions." }, { title: "Automated Bug Report Triage", description: "Use AI to automatically categorize and prioritize incoming bug reports, allowing your dev team to fix critical issues faster." }] }
    };
    aiRecommendations.manufacturing = aiRecommendations.service;
    aiRecommendations.other = aiRecommendations.service;

    function updateProgressBar() {
        const progress = ((currentStep - 1) / (totalSteps - 1)) * 100;
        const progressBar = document.getElementById('progress-bar');
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
            progressBar.textContent = `${Math.round(progress)}%`;
        }
        const progressBarContainer = document.getElementById('progress-bar-container');
        if(progressBarContainer){
             progressBarContainer.style.display = (currentStep > 1 && currentStep < 5) ? 'block' : 'none';
        }
    }
    
    function nextStep(step) {
        document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        const nextStepEl = document.getElementById(`step-${step}`);
        if (nextStepEl) {
            nextStepEl.classList.add('active');
            currentStep = step;
        }

        if (currentStep === 5) startCountdown();
        else stopCountdown();

        updateProgressBar();
        window.scrollTo({ top: document.getElementById('ai-app-section').offsetTop, behavior: 'smooth' });
    }

    function prevStep(step) {
        document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        const prevStepEl = document.getElementById(`step-${step}`);
        if (prevStepEl) {
            prevStepEl.classList.add('active');
            currentStep = step;
        }
        updateProgressBar();
        window.scrollTo({ top: document.getElementById('ai-app-section').offsetTop, behavior: 'smooth' });
    }

    let countdownInterval;
    function stopCountdown() {
        clearInterval(countdownInterval);
    }

    function startCountdown() {
        const countdownElement = document.getElementById('countdown');
        if (!countdownElement) return;

        let deadline = localStorage.getItem('countdownDeadline');
        if (!deadline) {
            deadline = new Date().getTime() + 8 * 60 * 60 * 1000;
            localStorage.setItem('countdownDeadline', deadline);
        }

        stopCountdown();

        const updateTimer = () => {
            const now = new Date().getTime();
            const time = deadline - now;

            if (time < 0) {
                clearInterval(countdownInterval);
                countdownElement.textContent = "OFFER EXPIRED";
                const buyButton = document.getElementById('buy-btn-1');
                if(buyButton) {
                  buyButton.style.pointerEvents = 'none';
                  buyButton.classList.add('opacity-50');
                }
                return;
            }

            const hours = Math.floor((time % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((time % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((time % (1000 * 60)) / 1000);
            
            countdownElement.textContent = `${hours.toString().padStart(2,'0')}:${minutes.toString().padStart(2,'0')}:${seconds.toString().padStart(2,'0')}`;
        };

        updateTimer();
        countdownInterval = setInterval(updateTimer, 1000);
    }

    function calculateAiReadinessScore() {
        let baseScore = 300;
        const familiarity = document.getElementById('q4').value;
        const industry = document.getElementById('q1').value;
        const marketing = document.getElementById('q2').value;

        switch (familiarity) {
            case 'not_familiar': baseScore += 150; break;
            case 'somewhat_familiar': baseScore += 300; break;
            case 'very_familiar': baseScore += 450; break;
        }
        if (industry === 'saas' || industry === 'ecommerce') baseScore += 50;
        if (marketing === 'digital_marketing') baseScore += 25;

        return Math.min(850, baseScore + Math.floor(Math.random() * 25));
    }

    function calculateLeadScore(aiScore) {
        let score = 0;
        const ambition = document.getElementById('q_ambition').value;
        if (ambition === 'revenue') score += 25;
        else if (ambition === 'profit') score += 15;
        else score += 5;
        const urgency = document.getElementById('q_urgency').value;
        if (urgency === 'critical') score += 25;
        else if (urgency === 'significant') score += 10;
        const authority = document.getElementById('q_authority').value;
        if (authority === 'decision_maker') score += 15;
        else if (authority === 'influencer') score += 5;
        if (aiScore <= 579) score += 35;
        else if (aiScore <= 669) score += 20;
        else if (aiScore <= 739) score += 10;

        return Math.min(100, score);
    }

    function updateScoreGauge(score) {
        const scoreText = document.getElementById('score-text');
        const scoreNeedle = document.getElementById('score-needle');
        const scoreFeedback = document.getElementById('score-feedback');

        let current = 300;
        const timer = setInterval(() => {
            current += 5;
            if (current > score) current = score;
            scoreText.textContent = current;
            if (current >= score) clearInterval(timer);
        }, 10);

        const percentage = (score - 300) / 550;
        scoreNeedle.style.left = `${percentage * 100}%`;

        if (score < 580) {
            scoreFeedback.innerHTML = "<strong class='text-red-500'>Poor (300-579):</strong> This score indicates a high risk of being outpaced by competitors. Your business has significant foundational opportunities to integrate AI, and Pariss United can help build a strategy from the ground up.";
        } else if (score < 670) {
            scoreFeedback.innerHTML = "<strong class='text-yellow-500'>Average (580-669):</strong> You have some basic systems in place, but your business isn't yet leveraging AI for a competitive advantage. Pariss United specializes in optimizing these areas to accelerate your growth.";
        } else if (score < 740) {
            scoreFeedback.innerHTML = "<strong class='text-lime-500'>Good (670-739):</strong> Your business is using AI effectively in some areas. Now is the time to scale those successes. Pariss United can provide the advanced strategies to turn 'good' into 'excellent'.";
        } else {
            scoreFeedback.innerHTML = "<strong class='text-green-500'>Excellent (740-850):</strong> Congratulations! Your business is a leader in its use of AI. Pariss United can provide the expert, high-level strategies to help you solidify your market position and explore new frontiers.";
        }
    }

    function validateAndGoToStep2() {
        const form = document.getElementById('user-info-form');
        const inputs = form.querySelectorAll('input[required], textarea[required]');
        const errorMsg = document.getElementById('form-error-msg');
        let isValid = true;

        inputs.forEach(input => {
            input.classList.remove('invalid');
            if (!input.value.trim()) {
                input.classList.add('invalid');
                isValid = false;
            }
        });

        if (!isValid) {
            errorMsg.style.display = 'block';
            form.classList.add('shake');
            setTimeout(() => form.classList.remove('shake'), 820);
            return;
        }

        errorMsg.style.display = 'none';
        userData = {
            fullName: document.getElementById('fullName').value,
            email: document.getElementById('email').value,
            phone: document.getElementById('phone').value,
            website: document.getElementById('website').value,
            businessDescription: document.getElementById('businessDescription').value,
        };
        
        nextStep(2);
    }

    function generateEvaluation() {
        const aiScore = calculateAiReadinessScore();
        leadScore = calculateLeadScore(aiScore);
        
        // *** FIX: ADD ALL DATA TO USERDATA AND SEND TO HUBSPOT ***
        userData.aiScore = aiScore;
        userData.leadScore = leadScore;
        userData.q1 = document.getElementById('q1').value;
        userData.q2 = document.getElementById('q2').value;
        userData.q3 = document.getElementById('q3').value;
        userData.q4 = document.getElementById('q4').value;
        userData.q_ambition = document.getElementById('q_ambition').value;
        userData.q_urgency = document.getElementById('q_urgency').value;
        userData.q_authority = document.getElementById('q_authority').value;
        sendToHubSpot(userData);

        if (leadScore >= 85) {
            const email = encodeURIComponent(userData.email);
            window.location.href = `booking.html?email=${email}`;
            return; 
        }

        updateScoreGauge(aiScore);
        const industry = document.getElementById('q1').value;
        const challenge = document.getElementById('q3').value;
        let recommendations = aiRecommendations[industry]?.[challenge] || aiRecommendations.other.lead_generation;
        const allRecos = Object.values(aiRecommendations[industry] || aiRecommendations.other).flat();
        let finalRecommendations = [...recommendations];
        let potentialRecos = allRecos.filter(reco => !finalRecommendations.some(r => r.title === reco.title));
        while (finalRecommendations.length < 5 && potentialRecos.length > 0) {
            finalRecommendations.push(potentialRecos.splice(Math.floor(Math.random() * potentialRecos.length), 1)[0]);
        }
        const resultsContainer = document.getElementById('evaluation-results');
        resultsContainer.innerHTML = '';
        finalRecommendations.slice(0, 5).forEach(reco => {
            const card = document.createElement('div');
            card.className = 'bg-gray-50 p-6 rounded-lg border border-gray-200 transform hover:-translate-y-1 transition-transform';
            card.innerHTML = `<h4 class="font-bold text-lg text-gray-800">${reco.title}</h4><p class="text-gray-600 mt-2 text-sm">${reco.description}</p>`;
            resultsContainer.appendChild(card);
        });
        nextStep(4);
    }

    // *** FIX: ADDED FUNCTION TO SEND DATA TO HUBSPOT VIA NETLIFY FUNCTION ***
    async function sendToHubSpot(data) {
        try {
            await fetch('/.netlify/functions/hubspot-contact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            console.log('Lead data successfully sent to HubSpot.');
        } catch (error) {
            console.error('Error sending data to HubSpot:', error);
        }
    }
    
    // --- Event Listener Setup ---
    document.getElementById('user-info-form')?.addEventListener('submit', (e) => { e.preventDefault(); validateAndGoToStep2(); });
    document.getElementById('go-to-step3-btn')?.addEventListener('click', () => nextStep(3));
    document.getElementById('generate-roadmap-btn')?.addEventListener('click', generateEvaluation);
    document.getElementById('lead-the-pack-btn')?.addEventListener('click', () => nextStep(5));
    
    document.getElementById('back-to-step1-btn')?.addEventListener('click', () => prevStep(1));
    document.getElementById('back-to-step2-btn')?.addEventListener('click', () => prevStep(2));
    document.getElementById('back-to-step3-btn')?.addEventListener('click', () => prevStep(3));

    document.getElementById('no-thanks-step4-btn')?.addEventListener('click', () => nextStep(6));
    document.getElementById('no-thanks-step5-btn')?.addEventListener('click', () => nextStep(6));
    document.getElementById('no-thanks-step6-btn')?.addEventListener('click', () => nextStep(7));


    // --- Chatbot Logic ---
    const chatbotToggle = document.getElementById('chatbot-toggle');
    const chatWindow = document.getElementById('chat-window');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    let conversationState = 'start';
    
    if(chatbotToggle){
        chatbotToggle.addEventListener('click', () => {
            chatWindow.classList.toggle('open');
            if (chatWindow.classList.contains('open') && chatMessages.children.length === 0) {
                 setTimeout(startConversation, 500);
            }
        });
    }

    const addBotMessage = (message, buttons = []) => {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message bot-message';
        messageDiv.innerHTML = message;
        chatMessages.appendChild(messageDiv);

        const existingButtons = document.getElementById('chat-reply-buttons');
        if (existingButtons) {
            existingButtons.remove();
        }

        if (buttons.length > 0) {
            const buttonContainer = document.createElement('div');
            buttonContainer.id = 'chat-reply-buttons';
            buttons.forEach(button => {
                const btn = document.createElement('button');
                btn.className = 'reply-btn';
                btn.textContent = button.text;
                btn.onclick = () => handleReply(button.payload);
                buttonContainer.appendChild(btn);
});
            chatMessages.appendChild(buttonContainer);
        }

        chatMessages.scrollTop = chatMessages.scrollHeight;
        return messageDiv;
    };

    const addUserMessage = (message) => {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message user-message';
        messageDiv.textContent = message;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    };
    
    const handleReply = (payload) => {
        const buttonText = conversationTree[conversationState].buttons.find(b => b.payload === payload).text;
        addUserMessage(buttonText);
        
        const existingButtons = document.getElementById('chat-reply-buttons');
        if (existingButtons) {
            existingButtons.remove();
        }

        conversationState = payload;
        setTimeout(runConversation, 500);
    };

    const runConversation = () => {
        const node = conversationTree[conversationState];
        if (node) {
            addBotMessage(node.message, node.buttons);
            if (node.action) {
                node.action();
            }
        }
    };
    
    const conversationTree = {
        'start': {
            message: "Hello! I'm Celeste, your AI Business Advisor. I can help you understand how AI can transform your business. What's your primary goal today?",
            buttons: [
                { text: "Find my AI Score", payload: "get_score" },
                { text: "Learn about services", payload: "learn_services" },
                { text: "Just browsing", payload: "browsing" }
            ]
        },
        'get_score': {
            message: "Excellent choice! The AI Score is the best way to get a custom roadmap for your business. It's free and takes about 60 seconds.",
            buttons: [{