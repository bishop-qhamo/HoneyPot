#!/bin/bash
# HoneyPot Setup and Run Script for Linux/Mac

clear
echo "================================"
echo "  HoneyPot System Management"
echo "================================"
echo ""

show_menu() {
    echo "Available commands:"
    echo "  1. Setup (install dependencies)"
    echo "  2. Start HoneyPot Server"
    echo "  3. Start Dashboard"
    echo "  4. Show Status"
    echo "  5. Show Recent Alerts"
    echo "  6. Show Recent Sessions"
    echo "  7. Show Top IPs"
    echo "  8. Export Data"
    echo "  9. Exit"
    echo ""
}

setup() {
    echo ""
    echo "Installing dependencies..."
    
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -r requirements.txt
    
    echo ""
    echo "Setup complete! You can now run the HoneyPot."
    echo ""
}

run_honeypot() {
    echo ""
    echo "Starting HoneyPot Server..."
    echo "Listening on ports 22 (SSH) and 23 (Telnet)"
    echo "Press Ctrl+C to stop"
    echo ""
    
    source venv/bin/activate
    python3 honeyPot.py
}

run_dashboard() {
    echo ""
    echo "Starting Dashboard..."
    echo "Access at: http://localhost:5000"
    echo "Press Ctrl+C to stop"
    echo ""
    
    source venv/bin/activate
    python3 dashboard.py
}

show_status() {
    echo ""
    source venv/bin/activate
    python3 manage.py status
}

show_alerts() {
    echo ""
    source venv/bin/activate
    python3 manage.py alerts --limit 15
}

show_sessions() {
    echo ""
    source venv/bin/activate
    python3 manage.py sessions --limit 15
}

show_top_ips() {
    echo ""
    source venv/bin/activate
    python3 manage.py top-ips --limit 10
}

export_data() {
    echo ""
    read -p "Enter export format (json/csv) [json]: " format
    format=${format:-json}
    read -p "Enter days to export [30]: " days
    days=${days:-30}
    
    source venv/bin/activate
    python3 manage.py export --format $format --days $days
}

# Main loop
while true; do
    show_menu
    read -p "Enter your choice (1-9): " choice
    
    case $choice in
        1) setup ;;
        2) run_honeypot ;;
        3) run_dashboard ;;
        4) show_status ;;
        5) show_alerts ;;
        6) show_sessions ;;
        7) show_top_ips ;;
        8) export_data ;;
        9) echo ""; echo "Goodbye!"; echo ""; exit 0 ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
    
    read -p "Press Enter to continue..."
    clear
done
