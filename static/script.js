async function analyzeSample() {
    const sampleData = {
        // NSL-KDD Features
        'duration': 0,
        'protocol_type': 'tcp',
        'service': 'http',
        // ... Add all required features from both datasets
        // CIC-IDS Features
        'Dst Port': 80,
        'Protocol': 6,
        // ... Add all required features
    };

    try {
        const response = await fetch('/api/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(sampleData)
        });

        const result = await response.json();
        displayResults(result);
    } catch (error) {
        console.error('Error:', error);
    }
}

function displayResults(data) {
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `
        <h3>Results:</h3>
        <p>NSL-KDD Model: ${data.nsl_prediction}</p>
        <p>CIC-IDS Model: ${data.ids_prediction}</p>
        <h4 class="${data.final_verdict.includes('Attack') ? 'attack' : 'normal'}">
            ${data.final_verdict}
        </h4>
    `;
}