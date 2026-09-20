# wsgi.py — entry point that loads BOTH apps without touching app.py
from app import app
import wix_app

wix_app.attach(app)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
