# Deploy to Render.com

## Quick Setup

1. **Push your code to GitHub** (if not already there)
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```

2. **Go to Render.com**
   - Sign up/Login at https://render.com
   - Click "New +" → "Web Service"

3. **Connect GitHub**
   - Connect your GitHub account
   - Select your repository

4. **Configure the service**
   - **Name**: bullet-basecamp (or whatever you want)
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free

5. **Environment Variables** (optional - render.yaml handles this)
   - FLASK_ENV: production
   - FLASK_SECRET_KEY: (auto-generated)
   - ADMIN_USERNAME: admin
   - ADMIN_PASSWORD: BulletBasecamp2024!@#

6. **Deploy!**
   - Click "Create Web Service"
   - Wait for build to complete (2-3 minutes)

## Your site will be available at:
`https://your-app-name.onrender.com`

## Admin Access:
- URL: `https://your-app-name.onrender.com/admin`
- Username: admin
- Password: BulletBasecamp2024!@#

## Notes:
- Free tier has some limitations but works great for demos
- Site will sleep after 15 minutes of inactivity
- First load after sleep takes 30-60 seconds
- Perfect for client demos and temporary hosting 