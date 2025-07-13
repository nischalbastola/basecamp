# Bullet Basecamp - Motorcycle Tours & Rentals

A modern, responsive website for Bullet Basecamp - a premium motorcycle workshop offering tours, rentals, and repair services in the Himalayan region.

## 🏍️ Features

### Frontend
- **Modern Design**: Clean, professional interface with orange branding (#FF6B35)
- **Responsive Layout**: Mobile-first design that works on all devices
- **Interactive Elements**: Smooth animations and hover effects
- **Video Backgrounds**: Hero videos on all pages with fallback images
- **Search Functionality**: Real-time filtering for tours and rentals
- **Contact Forms**: Validated contact forms with file attachments

### Backend (Flask)
- **Admin Dashboard**: Complete management system for content
- **Tour Management**: Add, edit, delete tour packages with image uploads
- **Rental Management**: Manage motorcycle rental fleet
- **Message System**: View and manage customer inquiries
- **Staff Management**: Add/remove admin staff accounts
- **Session Management**: Secure authentication with auto-logout
- **File Upload**: Support for image uploads with validation
- **JSON Storage**: Lightweight data storage using JSON files

### Pages
1. **Home**: Hero video, featured services, company overview
2. **Tours**: Browse available motorcycle tours with search
3. **Rentals**: View rental fleet with specifications and search
4. **Repairs**: Motorcycle repair and maintenance services
5. **About**: Company story and team information
6. **Contact**: Contact form and business information
7. **Admin System**: Complete backend management interface

## 🛠️ Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Backend**: Flask (Python)
- **Styling**: Custom CSS with Inter font
- **Data Storage**: JSON files
- **File Uploads**: Werkzeug secure file handling
- **Session Management**: Flask sessions with timeout

## 📁 Project Structure

```
basecamp/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── data/                  # JSON data files
│   ├── tours.json        # Tour packages data
│   ├── rentals.json      # Rental bikes data
│   ├── inquiries.json    # Customer messages
│   ├── staff.json        # Admin staff accounts
│   └── security.log      # Security and access logs
├── static/               # Static assets
│   ├── css/
│   │   └── style.css     # Main stylesheet
│   ├── js/
│   │   └── main.js       # JavaScript functionality
│   ├── images/           # Default images
│   ├── uploads/          # User uploaded images
│   └── videos/           # Hero background videos
└── templates/            # Jinja2 templates
    ├── base.html         # Base template
    ├── index.html        # Homepage
    ├── tours.html        # Tours page
    ├── rentals.html      # Rentals page
    ├── repairs.html      # Repairs page
    ├── about.html        # About page
    ├── contact.html      # Contact page
    ├── thank_you.html    # Thank you page
    └── admin/            # Admin templates
        ├── login.html    # Admin login
        ├── dashboard.html # Admin dashboard
        ├── tours.html    # Tour management
        ├── rentals.html  # Rental management
        ├── staff.html    # Staff management
        └── messages.html # Message management
```

## 🚀 Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd basecamp
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the website**
   - Frontend: http://localhost:5000
   - Admin Panel: http://localhost:5000/admin/login

## 🔐 Admin Access

- **Username**: admin
- **Password**: basecamp2024
- **Features**: Tour/rental management, customer messages, staff accounts

## 🎨 Design System

- **Primary Color**: #FF6B35 (Orange)
- **Typography**: Inter font family
- **Layout**: CSS Grid and Flexbox
- **Responsive**: Mobile-first approach
- **Animation**: Smooth transitions and hover effects

## 📱 Responsive Design

- **Desktop**: Full layout with sidebar navigation
- **Tablet**: Adapted grid system
- **Mobile**: Hamburger menu, stacked content
- **Touch**: Optimized for touch interactions

## 🔧 Key Features

### Search Functionality
- Real-time filtering on tours and rentals pages
- Search by title, description, difficulty, specifications
- Live results counter with smooth animations

### Admin System
- Complete CRUD operations for all content
- Image upload and management
- Customer inquiry management
- Session timeout and security features
- Toast notifications for user feedback

### Security Features
- Session-based authentication
- 30-minute session timeout
- Activity tracking and auto-logout
- Secure file upload validation
- Admin-only route protection

## 📊 Data Management

All data is stored in JSON files for simplicity:
- `tours.json`: Tour packages with pricing and details
- `rentals.json`: Motorcycle fleet with specifications
- `inquiries.json`: Customer messages and contact info
- `staff.json`: Admin staff accounts and roles

## 🎯 Performance

- Optimized images and videos
- Minimal JavaScript for fast loading
- CSS Grid for efficient layouts
- Compressed assets and caching headers

## 📞 Contact

For questions about this project, contact the development team.

---

**Built with ❤️ following the design.json specifications exactly** 