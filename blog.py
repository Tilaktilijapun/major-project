from flask import Blueprint, render_template, request, jsonify
from datetime import datetime
from models import BlogPost, User
from flask_login import login_required, current_user
from extensions import db

blog_bp = Blueprint('blog', __name__)

@blog_bp.route('/blog')
@login_required
def blog_page():
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).paginate(page=page, per_page=6, error_out=False)
    return render_template('blog.html', posts=posts.items)

@blog_bp.route('/blog/api/posts')
def get_posts():
    try:
        page = request.args.get('page', 1, type=int)
        category = request.args.get('category', '')
        search = request.args.get('search', '')
        per_page = 6

        query = BlogPost.query
        if category and category != 'all':
            query = query.filter_by(category=category)
        if search:
            query = query.filter((BlogPost.title.ilike(f'%{search}%')) | (BlogPost.content.ilike(f'%{search}%')))

        posts = query.order_by(BlogPost.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'posts': [{
                'id': str(post.id),  # Convert UUID to string
                'title': post.title,
                'content': post.content,
                'author': {'username': post.author.username} if post.author else {'username': 'Unknown'},
                'created_at': post.created_at.isoformat(),
                'category': post.category or 'all',
                'image_url': post.image_url
            } for post in posts.items],
            'total_pages': posts.pages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@blog_bp.route('/blog/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category', 'all')
        image_url = request.form.get('image_url')
        if not title or not content:
            return jsonify({'error': 'Title and content are required'}), 400
        
        # Generate UUID for new post
        import uuid
        new_post = BlogPost(
            id=str(uuid.uuid4()),  # Generate UUID for post
            title=title,
            content=content,
            author_id=current_user.id,
            created_at=datetime.utcnow(),
            category=category,
            image_url=image_url
        )
        db.session.add(new_post)
        db.session.commit()
        return jsonify({'message': 'Post created successfully'})
    return render_template('blog_create.html')

@blog_bp.route('/blog/<post_id>')
def view_post(post_id):
    post = BlogPost.query.get_or_404(post_id)  # Query by UUID string
    return render_template('blog_view.html', post=post)