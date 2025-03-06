from app import create_app
from flask_cors import CORS
from flask import render_template

app = create_app()
CORS(app)

@app.route('/<path:path>')
    def catch_all(path):
        return render_template('404.html'), 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
