from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Vulnerable Test Server</h1><p>GraphQL endpoint at /graphql</p>"

@app.route('/graphql', methods=['POST'])
def graphql():
    """
    A mock GraphQL endpoint that is vulnerable to Introspection.
    It responds to standard __schema queries used by PRAWN.
    """
    try:
        data = request.get_json()
        query = data.get("query", "")

        # Simple detection of a PRAWN Introspection query
        if "__schema" in query or "IntrospectionQuery" in query:
            return jsonify({
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": [
                            {"name": "User", "kind": "OBJECT"},
                            {"name": "AdminPrivateData", "kind": "OBJECT"}
                        ],
                        "directives": [{"name": "deprecated"}]
                    }
                }
            })
        
        # Handle basic health probe
        if "{ __typename }" in query:
            return jsonify({"data": {"__typename": "Query"}})

        return jsonify({"errors": [{"message": "Unknown query"}]}), 400

    except Exception as e:
        return jsonify({"errors": [{"message": str(e)}]}), 500

@app.route('/login', methods=['POST'])
def login():
    # Simulated SQLi
    user = request.form.get('username')
    if "' OR 1=1" in str(user):
        return "Logged in as Admin", 200
    return "Login Failed", 401

if __name__ == '__main__':
    app.run(port=8000)