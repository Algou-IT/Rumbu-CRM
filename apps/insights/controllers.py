from flask import request, jsonify
from . import insights
from ..models.general.task import Task


@insights.route('/task-completion', methods=['GET'])
def get_task_completion():
    company_id = request.args.get('company_id')
    
    # Get all tasks for the specified company
    tasks = Task.query.filter_by(company_id=company_id).all()
    
    # Calculate the count of completed and pending tasks
    completed_count = sum(1 for task in tasks if task.status)
    pending_count = len(tasks) - completed_count  # Total tasks minus completed tasks
    
    return jsonify({
        'completed': completed_count,
        'pending': pending_count
    })
