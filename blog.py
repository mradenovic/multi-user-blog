"""Udacity Project: Multi User Blog"""
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

SECRET = 'fart'


def render_str(template, **params):
    template = jinja_env.get_template(template)
    return template.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Class for handling common Blog tasks"""
    user = None

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

# user stuff


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
    """Class for User model in datastore"""
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


# blog stuff

class BlogModel(db.Model):

    @classmethod
    def by_id(cls, model_id):
        return cls.get_by_id(int(model_id))


class Post(BlogModel):
    """Class for Post model in datastore"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    _render_text = None

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Like(BlogModel):
    post = db.ReferenceProperty(Post, required=True)
    liked_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Comment(BlogModel):
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post, required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    _render_text = None

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", comment=self)


class BlogFront(BlogHandler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostHandler(BlogHandler):
    """Class for handling common Blog Post tasks"""
    blog_post = None
    user_is_post_owner = None
    like = None
    error = None

    def get(self, action, post_id):
        """Method for handling common Blog Post tasks"""
        if not self.user and action != 'view':
            self.redirect('/login')
            return
        if action not in ['create']:
            if self.set_blog_post(post_id):
                self.set_like()
                self.set_user_is_post_owner(post_id)
            else:
                return

        if action in ['edit', 'delete'] and not self.user_is_post_owner:
            self.error = 'you can %s only your own post!' % action
        elif action in ['like'] and self.user_is_post_owner:
            self.error = 'you can not %s your own post!' % action
        elif action in ['like'] and self.like:
            self.error = 'you can %s any post only once!' % action

        if self.error:
            self.render("permalink.html", post=self.blog_post,
                        edit_error=self.error)

    def set_user_is_post_owner(self, post_id):
        blog_post = Post.by_id(post_id)
        is_owner = self.user and self.user.key() == blog_post.created_by.key()
        self.user_is_post_owner = is_owner

    def set_blog_post(self, post_id):
        self.blog_post = Post.by_id(post_id)
        return self.blog_post

    def set_like(self):
        self.like = self.user and Like.gql(
            'WHERE post = :post AND liked_by = :user',
            post=self.blog_post.key(),
            user=self.user.key()).get()
        return self.like


class PostView(PostHandler):
    """Class for handling Blog Post tasks"""

    def get(self, action, post_id):
        super(PostView, self).get(action, post_id)

        if not self.blog_post:
            self.error(404)
            return

        self.render("permalink.html", post=self.blog_post)


class PostDelete(PostHandler):

    def get(self, action, post_id):
        super(PostDelete, self).get(action, post_id)

        if not self.user_is_post_owner:
            return

        for comment in self.blog_post.comment_set:
            comment.delete()
        self.blog_post.delete()
        self.redirect('/')


class PostCreate(PostHandler):

    def get(self, action, post_id):
        super(PostCreate, self).get(action, post_id)
        if self.request.path.find('edit') > -1:
            return
        self.render("post-form.html", action=action)

    def post(self, action, post_id):
        """Create new blog post or edit existing one"""
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
                p = Post(subject=subject, content=content,
                         created_by=self.user)
            else:
                p.subject = subject
                p.content = content
            p.put()
            self.redirect('/post/view/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("post-form.html", subject=subject,
                        content=content, error=error)


class PostEdit(PostCreate):

    def get(self, action, post_id):
        super(PostEdit, self).get(action, post_id)
        if not self.user_is_post_owner:
            return
        params = {}
        params['subject'] = self.blog_post.subject
        params['content'] = self.blog_post.content
        params['action'] = action
        self.render('post-form.html', **params)


class PostLike(PostHandler):

    def get(self, action, post_id):
        super(PostLike, self).get(action, post_id)
        if not self.blog_post or self.error:
            return
        params = {}
        like = Like(post=self.blog_post, liked_by=self.user)
        key = like.put()
        # get updated object
        params['post'] = db.get(key).post
        self.render("permalink.html", **params)


class CommentPermission(object):
    """Class to augument comment handling classes"""
    comment = None
    blog_post = None
    user_is_comment_owner = None
    message = None
    params = {}

    def init_env(self, action, entity_id):
        if action in ['comment']:
            self.blog_post = Post.by_id(entity_id)
        elif action in ['edit', 'delete']:
            self.comment = Comment.by_id(entity_id)
            if self.comment:
                self.user_is_comment_owner = self.user and self.user.key(
                ) == self.comment.created_by.key()
                self.blog_post = self.comment.post

    def validate(self, action, entity_id):
        """Validate if action is permited on entity"""
        self.init_env(action, entity_id)
        if not self.blog_post or (action in ['edit', 'delete'] and not self.comment):
            return False
        elif not self.user:
            self.message = 'Only logged in users can %s!' % action
        elif action in ['edit', 'delete'] and not self.user_is_comment_owner:
            self.message = 'You can %s only your own comment!' % action
        return True


class PostComment(BlogHandler, CommentPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                params['action'] = action
            params['post'] = self.blog_post
            self.render("permalink.html", **params)

    def post(self, action, post_id):
        """Post comment"""
        if self.validate(action, post_id):
            content = self.request.get('content')

            if content:
                if self.comment:
                    self.comment.content = content
                else:
                    self.create_comment(content)
                key = self.comment.put()
                # get updated object
                self.blog_post = db.get(key).post
                error = ''
            else:
                error = "content, please!"
            self.render("permalink.html", post=self.blog_post, error=error)

    def create_comment(self, content):
        params = {}
        params['content'] = content
        params['post'] = self.blog_post
        params['created_by'] = self.user
        self.comment = Comment(**params)


class CommentEdit(PostComment):

    def get(self, action, comment_id):
        if self.validate(action, comment_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                params['action'] = action
                params['content'] = self.comment.content
            params['post'] = self.blog_post
            self.render("permalink.html", **params)


class CommentDelete(BlogHandler, CommentPermission):

    def get(self, action, comment_id):
        if self.validate(action, comment_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                self.comment.delete()
            params['post'] = self.blog_post
            self.render("permalink.html", **params)


# Unit 2 HW's
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
    """Class for nadling signup tasks"""
    username = None
    password = None
    verify = None
    email = None

    def get(self):
        self.render("signup-form.html")

    def post(self):
        """Post signup data"""
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
        # make sure the user doesn't already exist
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

app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/post/(view)/([0-9]+)', PostView),
                               ('/post/(edit)/([0-9]+)', PostEdit),
                               ('/post/(delete)/([0-9]+)', PostDelete),
                               ('/post/(create)/()', PostCreate),
                               ('/post/(like)/([0-9]+)', PostLike),
                               ('/post/(comment)/([0-9]+)', PostComment),
                               ('/comment/(edit)/([0-9]+)', CommentEdit),
                               ('/comment/(delete)/([0-9]+)', CommentDelete),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)],
                              debug=True)
