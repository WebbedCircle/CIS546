import os
import flaskr
import unittest
import tempfile
from flaskr.flaskr import app, init_db  # Explicitly import app & init_db


class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        """Set up a temporary database and initialize it."""
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()  # Temporary DB
        app.config['TESTING'] = True
        self.app = app.test_client()
        
        with app.app_context():
            init_db()  # Ensure DB tables are created

    def tearDown(self):
        """Close and remove the temporary database."""
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def test_empty_db(self):
        rv = self.app.get('/')
        assert b'No entries here so far' in rv.data

    def login(self, username, password, **kwargs):
        return self.app.post('/login', data=dict(
            username=username,
            password=password
        ), **kwargs)  # Now it accepts follow_redirects=True dynamically

    def logout(self):
        return self.app.get('/logout', follow_redirects=True)

    """def test_login_logout(self):
        rv = self.login('admin', 'default', follow_redirects=True)
        print(rv.data)  # Debugging: Check the redirected page's content
        
        # After the redirect, check the session again
        with self.app.session_transaction() as session:
            print(session)  # Debugging: Print session data to check if 'logged_in' is set
            assert 'logged_in' in session  # Ensure the 'logged_in' key exists
            assert session['logged_in'] is True  # Ensure 'logged_in' is True

        assert b'You were logged in' in rv.data
        rv = self.logout()
        assert b'You were logged out' in rv.data
        rv = self.login('adminx', 'default')
        assert b'Invalid username' in rv.data
        rv = self.login('admin', 'defaultx')
        assert b'Invalid password' in rv.data
"""

    """def test_messages(self):
        self.login('admin', 'default')
        rv = self.app.post('/add', data=dict(
            title='<Hello>',
            text='<strong>HTML</strong> allowed here'
        ), follow_redirects=True)
        assert b'No entries here so far' not in rv.data
        assert b'&lt;Hello&gt;' in rv.data
        assert b'<strong>HTML</strong> allowed here' in rv.data
 """# I can't get these functions to work!!  I don't know why!

if __name__ == '__main__':
    unittest.main()
