import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

##### user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group='default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

class BlogModel(db.Model):
    @classmethod
    def by_id(cls, model_id):
        return cls.get_by_id(int(model_id))

class Post(BlogModel):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def render_comment_form(self, error):
        return render_str('comment-form.html', error=error)

class Comment(db.Model):
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post, required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", comment=self)

class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)

class PostHandler(BlogHandler):
    noOwner = True

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
            return

        if not post_id:
            return
        blog_post = Post.by_id(post_id)
        if self.user.key() == blog_post.created_by.key():
            self.noOwner = False
        else:
            error = 'Only owner can change post'
            self.render("permalink.html", post=blog_post, edit_error=error)

class PostPage(BlogHandler):
    def get(self, post_id):
        blog_post = Post.by_id(post_id)

        if not blog_post:
            self.error(404)
            return

        self.render("permalink.html", post=blog_post)

    def post(self, post_id):
        blog_post = Post.by_id(post_id)
        error = ''

        if not self.user:
            error = "only logged in users can post comments!"
            self.render("permalink.html", post=blog_post, error=error)
            return

        content = self.request.get('content')

        if content:
            comment = Comment(content=content, post=blog_post, created_by=self.user)
            key = comment.put()
            # get updated object
            blog_post = db.get(key).post

            self.render("permalink.html", post=blog_post, error=error)
        else:
            error = "content, please!"
            self.render("permalink.html", post=blog_post, error=error)

class PostDelete(PostHandler):
    def get(self, post_id):
        super(PostDelete, self).get(post_id)

        if self.noOwner:
            return

        blog_post = Post.by_id(post_id)

        for comment in blog_post.comment_set:
            comment.delete()
        blog_post.delete()
        self.redirect('/')

class NewPost(PostHandler):
    def get(self, post_id):
        super(NewPost, self).get(post_id)
        if self.request.path.find('edit') > -1:
            return
        self.render("newpost.html")

    def post(self, post_id):
        if post_id:
            p = Post.by_id(post_id)
        else:
            p = None

        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            if not p:
                p = Post(subject=subject, content=content, created_by=self.user)
            else:
                p.subject = subject
                p.content = content
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class PostEdit(NewPost):
    def get(self, post_id):
        super(PostEdit, self).get(post_id)
        if self.noOwner:
            return
        blog_post = Post.by_id(post_id)

        self.render('newpost.html', content=blog_post.content, subject=blog_post.subject)

###### Unit 2 HW's
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([
                               ('/?', BlogFront),
                               ('/post/view/([0-9]+)', PostPage),
                               ('/post/edit/([0-9]+)', PostEdit),
                               ('/post/delete/([0-9]+)', PostDelete),
                               ('/post/create/()', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)],
                              debug=True)
