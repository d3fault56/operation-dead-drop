"""Built-in demo artifacts. All domains are fictitious look-alikes; nothing is fetched."""

DEMOS = {
    "bank": {
        "title": "Bank Phishing",
        "subtitle": "Fake security alert with credential-harvesting link",
        "content": """From: Chase Fraud Prevention <alerts@chase-secure-verify.com>
Subject: [Action Required] Unusual sign-in activity detected on your account

Dear Valued Customer,

Our security team detected unusual sign-in activity on your Chase online banking account from a new device in Lagos, Nigeria.

For your protection, your account access has been restricted. To avoid permanent suspension, you must verify your identity within 24 hours.

Please log in and confirm your username, password, and the one-time verification code we send to your phone:

https://secure-login.chase.account-verify.xyz/auth/signin?session=8f2a91&redirect=https%3A%2F%2Fchase.com

If you do not complete verification by 11:59 PM tonight, your account and all linked cards will be suspended.

Thank you,
Chase Online Security Department""",
    },
    "job": {
        "title": "Fake Job Offer",
        "subtitle": "Recruiter scam requesting PII and an upfront fee",
        "content": """Hi there!

My name is Jessica Miller, Senior Hiring Manager at Amazon Logistics. We reviewed your resume on Indeed and you've been selected for a Remote Data Entry Assistant position. No experience needed — the role pays $45/hour, fully work from home.

To finalize your onboarding, please text me at (210) 555-0187 or message our recruitment team on Telegram @AmazonHR_Onboard.

We will need the following to set up payroll:
- Full name, address and date of birth
- Social Security number
- Bank account number and routing number for direct deposit
- A photo of your driver's license

You will also need to purchase a training kit and home-office equipment ($189.99) from our approved vendor, which will be reimbursed in your first paycheck. Payment can be sent via Zelle or Bitcoin.

This offer expires today, so please respond immediately. Keep this offer confidential until your start date.

Best regards,
Jessica Miller
amazon-careers-hr@gmail.com""",
    },
    "delivery": {
        "title": "Delivery Scam",
        "subtitle": "Smishing redelivery fee with look-alike domain",
        "content": """USPS: Your package USPS9400-1118-9922 could not be delivered due to an incomplete address. A $1.99 redelivery fee is required. Update your details within 12 hours or the package will be returned to sender: https://usps.redelivery-track.top/pay?id=US9400 Reply STOP to opt out.""",
    },
}
