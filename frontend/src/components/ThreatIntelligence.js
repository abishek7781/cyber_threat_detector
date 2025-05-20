import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  LinearProgress,
  IconButton,
  Collapse,
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  ExpandMore,
  ExpandLess,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

const ThreatScore = styled(Box)(({ theme, score }) => ({
  width: 120,
  height: 120,
  borderRadius: '50%',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: `conic-gradient(
    ${score <= 30 ? theme.palette.success.main : 
      score <= 70 ? theme.palette.warning.main : 
      theme.palette.error.main} 
    ${score * 3.6}deg,
    ${theme.palette.grey[800]} 0deg
  )`,
  position: 'relative',
  '&::before': {
    content: '""',
    position: 'absolute',
    width: '90%',
    height: '90%',
    borderRadius: '50%',
    background: theme.palette.background.paper,
  },
}));

const ThreatIntelligence = ({ data }) => {
  const [expanded, setExpanded] = React.useState(false);

  const getThreatColor = (level) => {
    switch (level) {
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'success';
      default:
        return 'default';
    }
  };

  const renderThreatSource = (source, data) => {
    if (!data) return null;

    return (
      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            {source}
          </Typography>
          <Grid container spacing={2}>
            {Object.entries(data).map(([key, value]) => {
              if (typeof value === 'boolean') {
                return (
                  <Grid item xs={6} sm={4} key={key}>
                    <Chip
                      icon={value ? <Warning /> : <CheckCircle />}
                      label={key.replace(/_/g, ' ')}
                      color={value ? 'error' : 'success'}
                      variant="outlined"
                    />
                  </Grid>
                );
              }
              if (typeof value === 'number') {
                return (
                  <Grid item xs={6} sm={4} key={key}>
                    <Typography variant="body2" color="textSecondary">
                      {key.replace(/_/g, ' ')}:
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={value}
                      color={value > 70 ? 'error' : value > 30 ? 'warning' : 'success'}
                      sx={{ height: 8, borderRadius: 4 }}
                    />
                    <Typography variant="body2">{value}%</Typography>
                  </Grid>
                );
              }
              if (Array.isArray(value)) {
                return (
                  <Grid item xs={12} key={key}>
                    <Typography variant="body2" color="textSecondary">
                      {key.replace(/_/g, ' ')}:
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {value.map((item, index) => (
                        <Chip
                          key={index}
                          label={item}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  </Grid>
                );
              }
              return null;
            })}
          </Grid>
        </CardContent>
      </Card>
    );
  };

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Security sx={{ mr: 1 }} />
          <Typography variant="h5" component="div">
            Threat Intelligence
          </Typography>
          <IconButton
            onClick={() => setExpanded(!expanded)}
            sx={{ ml: 'auto' }}
          >
            {expanded ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </Box>

        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <ThreatScore score={data.threat_score}>
                <Typography variant="h4" component="div">
                  {data.threat_score}
                </Typography>
              </ThreatScore>
              <Typography variant="h6" sx={{ mt: 2 }}>
                Threat Score
              </Typography>
              <Chip
                icon={<Security />}
                label={data.threat_level}
                color={getThreatColor(data.threat_level)}
                sx={{ mt: 1 }}
              />
            </Box>
          </Grid>

          <Grid item xs={12} md={8}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="h6" gutterBottom>
                Threat Reasons
              </Typography>
              {data.threat_reasons.map((reason, index) => (
                <Chip
                  key={index}
                  icon={<Warning />}
                  label={reason}
                  color="error"
                  variant="outlined"
                  sx={{ m: 0.5 }}
                />
              ))}
            </Box>

            <Collapse in={expanded}>
              <Box sx={{ mt: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Detailed Analysis
                </Typography>
                {renderThreatSource('URLhaus', data.intelligence_results?.urlhaus)}
                {renderThreatSource('PhishTank', data.intelligence_results?.phishtank)}
                {renderThreatSource('Google Safe Browsing', data.intelligence_results?.google_safe_browsing)}
                {renderThreatSource('IPQualityScore', data.intelligence_results?.ipqualityscore)}
                {renderThreatSource('AlienVault', data.intelligence_results?.alienvault)}
                {renderThreatSource('ThreatFox', data.intelligence_results?.threatfox)}
                {renderThreatSource('Cisco Talos', data.intelligence_results?.talos)}
              </Box>
            </Collapse>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};

export default ThreatIntelligence; 