exports.handler = async function(event, context) {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const contactData = JSON.parse(event.body);
  const HUBSPOT_API_KEY = process.env.HUBSPOT_API_KEY;

  // Map your website data to HubSpot's internal property names
  const hubspotProperties = {
    email: contactData.email,
    firstname: contactData.fullName ? contactData.fullName.split(' ')[0] : '',
    lastname: contactData.fullName ? contactData.fullName.split(' ').slice(1).join(' ') : '',
    phone: contactData.phone,
    website: contactData.website,
    business_description: contactData.businessDescription,
    ai_business_score: contactData.aiScore,
    ai_lead_score: contactData.leadScore,
    business_challenge: contactData.q3,
    ai_familiarity: contactData.q4,
    growth_goal: contactData.q_ambition,
    problem_urgency: contactData.q_urgency,
    decision_making_role: contactData.q_authority,
    ebook_download_source: contactData.ebook_download_source
  };

  const hubspotPayload = {
    properties: hubspotProperties
  };

  try {
    const response = await fetch(`https://api.hubapi.com/crm/v3/objects/contacts`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${HUBSPOT_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(hubspotPayload)
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`HubSpot API Error: ${response.status} ${errorBody}`);
    }

    const responseData = await response.json();

    return {
      statusCode: 200,
      body: JSON.stringify({ message: "Contact created successfully", data: responseData })
    };

  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Failed to create contact in HubSpot' })
    };
  }
};